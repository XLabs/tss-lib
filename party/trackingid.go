package party

import common "github.com/xlabs/tss-common"

// used to create trackingIDs for signing and DKG tasks
type task interface {
	GetDigest() []byte
	GetFaulties() common.UnSortedPartyIDs
	GetAuxiliaryData() []byte
	GetProtocolType() common.ProtocolType
	// TODO: add an isvalid method to ensure the task is valid.
}

func (s SigningTask) GetDigest() []byte {
	return s.Digest[:]
}

func (s SigningTask) GetFaulties() common.UnSortedPartyIDs {
	return s.Faulties
}

func (s SigningTask) GetAuxiliaryData() []byte {
	return s.AuxiliaryData
}

func (s SigningTask) GetProtocolType() common.ProtocolType {
	return s.ProtocolType
}

func (d DkgTask) GetDigest() []byte {
	return d.Seed[:]
}

func (d DkgTask) GetFaulties() common.UnSortedPartyIDs {
	return nil
}
func (d DkgTask) GetAuxiliaryData() []byte {
	return nil
}

func (d DkgTask) GetProtocolType() common.ProtocolType {
	return d.ProtocolType
}

func (p *Impl) createTrackingID(t task) *common.TrackingID {
	offlineMap := map[string]bool{}
	for _, v := range t.GetFaulties() {
		offlineMap[string(v.GetID())] = true
	}

	pids := make([]bool, len(p.peers))

	for i, v := range p.peers {
		if !offlineMap[string(v.GetID())] {
			pids[i] = true
		}
	}

	dgst := Digest{}
	copy(dgst[:], t.GetDigest())

	tid := &common.TrackingID{
		Digest:        dgst[:],
		PartiesState:  common.ConvertBoolArrayToByteArray(pids),
		AuxiliaryData: t.GetAuxiliaryData(),
		Protocol:      uint32(t.GetProtocolType().ToInt()),
	}

	return tid
}
