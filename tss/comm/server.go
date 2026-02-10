package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/xlabs/tss-lib/v2/tss"
	tsscommv1 "github.com/xlabs/tss-lib/v2/tss/internal/proto/tsscomm/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type connection struct {
	cc     *grpc.ClientConn
	stream tsscommv1.DirectLink_SendClient
}

type dialResponse struct {
	name string
	conn *connection
}

type dialRequest struct {
	hostname    string
	immediately bool //used to skip waiting in the scheduler backoff mechanism
}

type server struct {
	tsscommv1.UnimplementedDirectLinkServer
	ctx        context.Context
	logger     *zap.Logger
	socketPath string

	tssMessenger tss.ReliableMessenger

	peers      []*tss.Identity
	peerToCert map[string]*x509.Certificate
	// to ensure thread-safety without locks, only the sender goroutine is allowed to change this map.
	unsafeConnectionsMap map[string]*connection
	// used to schedule dial attempts to peers, the scheduler listens to this channel,
	// and once it deems a dial attempt should be made, it sends the hostname to dial to the dialer.
	dialingScheduleChan chan dialRequest
	// dialer sends dialResponse to this channel once a dial attempt is made to be picked up by
	// the sender, which uses the connections.
	dialResponse chan dialResponse
	// dialer waits on this channel to receive dial requests, and tries to dial to the requested peer.
	dialChan chan string
	// scheduler listens to this channel to reset the backoff attempts for a specific peer.
	resetAttemptsChan chan string

	fullyConnected chan struct{} // used to signal that the server is fully connected to all peers.
}

func (s *server) WaitForConnections(ctx context.Context) error {
	for {
		select {
		case <-s.ctx.Done():
			return ctx.Err()
		case <-s.fullyConnected:
			return nil
		}
	}
}

func (s *server) run() {
	go s.scheduler()
	go s.sender()

	for range runtime.NumCPU() {
		go s.dialer()
	}
}

const connectionCheckTime = time.Second * 5

// sender is responsible for sending messages to peers, also
// checks the health of connections by catching send errors and scheduling dialRequests.
//
// only this goroutine reads or writes to the connections map to ensure thread-safety without locks.
func (s *server) sender() {
	s.ensurePeerConnection()

	connectionCheckTicker := time.NewTicker(connectionCheckTime)
	defer connectionCheckTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			for _, con := range s.unsafeConnectionsMap {
				s.closeConnection(con)
			}

			return
		case o := <-s.tssMessenger.ProducedOutputMessages():
			s.send(o)
		case resp := <-s.dialResponse:
			s.receiveNewConnection(resp)
		case <-connectionCheckTicker.C:
			s.ensurePeerConnection()
		}
	}
}

func (s *server) receiveNewConnection(resp dialResponse) {
	// once we receive a new connection, we can reset the backoff attempts for this peer in the scheduler,
	select {
	case s.resetAttemptsChan <- resp.name:
	default:
		s.logger.Debug("couldn't send reset command to scheduler: channel blocked", zap.String("hostname", resp.name))
	}

	if _, ok := s.unsafeConnectionsMap[resp.name]; ok {
		// shouldn't open the same connection twice.
		// if a redial request is still needed, it will be enqueued again either
		// on the next send attempt, or once the sender's ticker pops.
		s.closeConnection(resp.conn)

		return
	}

	s.unsafeConnectionsMap[resp.name] = resp.conn

	s.logger.Info("established new direct link to peer",
		zap.String("hostname", resp.name),
		zap.Int("currentConnectedPeers", len(s.unsafeConnectionsMap)),
		zap.Int("totalPeers", len(s.peers)),
	)

	if len(s.unsafeConnectionsMap) == len(s.peers) {
		// signal to users that we're fully connected,
		// but don't block if the channel is already full.
		select {
		case s.fullyConnected <- struct{}{}:
		default:
		}
	}
}

func (s *server) closeConnection(con *connection) {
	if err := con.cc.Close(); err != nil {
		s.logger.Error(
			"couldn't close connection while shutting down",
			zap.Error(err),
		)
	}
}

// ensurePeerConnection creates dialRequest for any missing connection.
func (s *server) ensurePeerConnection() {
	if len(s.unsafeConnectionsMap) == len(s.peers) {
		return // all peers are connected, no need to force dial.
	}

	for _, id := range s.peers {
		hostname := id.NetworkName()
		if _, ok := s.unsafeConnectionsMap[hostname]; !ok {
			s.nonBlockingDialScheduling(dialRequest{
				hostname:    hostname,
				immediately: true,
			})
		}
	}
}

func (s *server) send(msg tss.Sendable) {
	for _, recipient := range msg.GetDestinations() {
		hostname := recipient.NetworkName()

		conn, ok := s.unsafeConnectionsMap[hostname]
		if !ok {
			s.nonBlockingDialScheduling(dialRequest{
				hostname:    hostname,
				immediately: false,
			})

			// This spams the logs, but it's useful for debugging.
			s.logger.Debug(
				"Couldn't send message to peer. No connection found.",
				zap.String("hostname", hostname),
			)

			continue
		}

		// Send blocks until the message is scheduled to be sent,
		// and returns an error if the connection is unhealthy.
		// Does not block until the message is actually sent,
		// so it won't cause head-of-line blocking on the sender side.
		if err := conn.stream.Send(msg.GetNetworkMessage()); err != nil {
			if err == io.EOF {
				_, err2 := conn.stream.CloseAndRecv()
				err = fmt.Errorf("stream closed by peer. peer's reason: %w", err2)
			}

			delete(s.unsafeConnectionsMap, hostname)

			redialRequested := s.nonBlockingDialScheduling(dialRequest{
				hostname:    hostname,
				immediately: false,
			})

			s.logger.Error(
				"couldn't send message to peer due to error.",
				zap.Error(err),
				zap.String("hostname", hostname),
				zap.Bool("redialRequestedNow", redialRequested),
				zap.Int("currentConnectedPeers", len(s.unsafeConnectionsMap)),
				zap.Int("totalPeers", len(s.peers)),
			)
		}
	}
}

// nonBlockingDialScheduling tries to schedule a dial request without blocking, may fail if channel is full.
func (s *server) nonBlockingDialScheduling(rqst dialRequest) bool {
	select {
	case s.dialingScheduleChan <- rqst:
		s.logger.Debug("requested redial", zap.String("hostname", rqst.hostname))

		return true
	default:
		s.logger.Debug("channel to request redial blocked dropping redial request to", zap.String("hostname", rqst.hostname))

		return false
	}
}

func (s *server) dialer() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case hostname := <-s.dialChan:
			if err := s.dial(hostname); err != nil {
				// schedule another dial attempt for this peer.
				redialRequested := s.nonBlockingDialScheduling(dialRequest{
					hostname:    hostname,
					immediately: false,
				})

				s.logger.Error(
					"couldn't create direct link to peer, will retry after some time",
					zap.Error(err),
					zap.String("hostname", hostname),
					zap.Bool("redialRequestedNow", redialRequested),
				)
			}
		}
	}
}

// scheduler is responsible for scheduling dial attempts to peers.
func (s *server) scheduler() {
	// using a heap instead of time.AfterFunc/ After to reduce the number of
	// goroutines generated to 0 (not including the scheduler itself).
	waiters := newBackoffHeap()

	for {
		dialTo := ""

		select {
		case <-s.ctx.Done():
			return
		case successfulDial := <-s.resetAttemptsChan:
			waiters.ResetAttempts(successfulDial)
		case <-waiters.WaitOnTimer():
			dialTo = waiters.Dequeue()
		case rqst := <-s.dialingScheduleChan:
			if rqst.immediately {
				dialTo = rqst.hostname // will drop down to the dialing section.
			} else {
				waiters.Enqueue(rqst.hostname)
			}
		}

		if dialTo == "" {
			continue // skip (nothing to dial to)
		}

		select {
		case s.dialChan <- dialTo:
			s.logger.Info("Scheduled dial to peer", zap.String("hostname", dialTo))
		case <-s.ctx.Done():
			return
		}
	}
}

func addDefaultPortIfMissing(addr string) (string, error) {
	_, _, err := net.SplitHostPort(addr)

	if err != nil {
		// Check if error is due to missing port
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			return addr + ":" + tss.DefaultPort, nil
		}

		return "", err
	}

	return addr, nil
}

func (s *server) dial(hostname string) error {
	crt, ok := s.peerToCert[hostname]
	if !ok {
		return fmt.Errorf("no cert found for peer %s", hostname)
	}

	pool := x509.NewCertPool()
	pool.AddCert(crt) // dialing to peer and accepting his cert only.

	dialToAddress, err := addDefaultPortIfMissing(hostname)
	if err != nil {
		return err
	}

	cc, err := grpc.Dial(dialToAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,                                    // tls 1.3
			Certificates: []tls.Certificate{*s.tssMessenger.GetCertificate()}, // our cert to be sent to the peer.
			RootCAs:      pool,
		})),
	)
	if err != nil {
		return err
	}

	stream, err := tsscommv1.NewDirectLinkClient(cc).Send(s.ctx)
	if err != nil {
		cc.Close()

		return err
	}

	d := dialResponse{
		name: hostname,
		conn: &connection{
			cc:     cc,
			stream: stream,
		},
	}

	select {
	case <-s.ctx.Done():
		cc.Close() // avoid leaking connections if we're shutting down while dialing.

		return s.ctx.Err()
	case s.dialResponse <- d:
	}

	return nil
}

func (s *server) Send(inStream tsscommv1.DirectLink_SendServer) error {
	clientId, err := s.getIdentityFromIncomingStream(inStream)
	if err != nil {
		s.logger.Warn(
			"did not accept incoming peer connection",
			zap.Error(err),
		)

		return status.Error(codes.Unauthenticated, fmt.Sprintf("couldn't accept incoming connection: %s", err))
	}

	for {
		m, err := inStream.Recv()
		if err != nil {
			if err == io.EOF {
				s.logger.Info(
					"closing input stream",
					zap.String("peer", clientId.Hostname),
				)

				return status.Error(codes.Canceled, "client closed the connection")
			}

			s.logger.Error(
				"error receiving from guardian. Closing connection",
				zap.Error(err),
				zap.String("peer", clientId.NetworkName()),
			)

			return status.Error(codes.Unknown, "error receiving message from client "+err.Error()) //fmt.Errorf("received error while receiving message: %w", err)
		}

		s.tssMessenger.HandleIncomingTssMessage(&tss.IncomingMessage{
			Source:  clientId,
			Content: m,
		})
	}
}

// getIdentityFromIncomingStream extracts the peer identity from the
// incoming TLS certificate embbeded into the stream.
// adds various checks to ensure the client is a valid guardian.
func (s *server) getIdentityFromIncomingStream(inStream tsscommv1.DirectLink_SendServer) (*tss.Identity, error) {
	p, ok := peer.FromContext(inStream.Context())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unable to retrieve peer from context")
	}

	// Extract AuthInfo (TLS information)
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unexpected peer transport credentials type, please use tls")
	}

	// check incoming TLS cert doesn't contain a chain (should be a leaf cert).
	// this is more of a precaution.
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no client certificate provided")
	}

	if len(tlsInfo.State.PeerCertificates) != 1 {
		return nil, status.Error(codes.PermissionDenied, "expected certificate to be a CA")
	}

	for _, chain := range tlsInfo.State.VerifiedChains {
		if len(chain) != 1 {
			return nil, status.Error(codes.PermissionDenied, "certificate has a chain")
		}
	}

	// Get the peer's certificate: The first element is the leaf certificate
	// that the connection is verified against
	clientCert := tlsInfo.State.PeerCertificates[0]

	if clientCert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, status.Error(codes.InvalidArgument, "certificate must use ECDSA")
	}

	if !clientCert.IsCA {
		return nil, status.Error(codes.PermissionDenied, "client certificate is not a CA, but a leaf certificate")
	}

	// fetch the party ID according to the public key used to verify this certificate (embbded in the cert).
	clientId, err := s.tssMessenger.FetchIdentity(clientCert)
	if err != nil {
		return nil, fmt.Errorf("client certificate wasn't found: %w", err)
	}

	return clientId, nil
}
