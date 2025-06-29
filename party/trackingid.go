package party

import common "github.com/xlabs/tss-common"

// used to create trackingIDs for signing and DKG tasks
type task interface {
	GetDigest() []byte
	GetFaulties() common.UnSortedPartyIDs
	GetAuxilaryData() []byte
}

func (s SigningTask) GetDigest() []byte {
	return s.Digest[:]
}

func (s SigningTask) GetFaulties() common.UnSortedPartyIDs {
	return s.Faulties
}

func (s SigningTask) GetAuxilaryData() []byte {
	return s.AuxilaryData
}

func (d DkgTask) GetDigest() []byte {
	return d.Seed[:]
}

func (d DkgTask) GetFaulties() common.UnSortedPartyIDs {
	return nil
}
func (d DkgTask) GetAuxilaryData() []byte {
	return nil
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
		Digest:       dgst[:],
		PartiesState: common.ConvertBoolArrayToByteArray(pids),
		AuxilaryData: t.GetAuxilaryData(),
	}

	return tid
}
