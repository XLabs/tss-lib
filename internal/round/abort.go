package round

import (
	"github.com/xlabs/tss-lib/v2/internal/party"
	"github.com/xlabs/tss-lib/v2/tss"
)

// Abort is an empty round containing a list of parties who misbehaved.
type Abort struct {
	*Helper
	Culprits []party.ID
	Err      error
}

func (Abort) VerifyMessage(Message) error                           { return nil }
func (Abort) StoreMessage(Message) error                            { return nil }
func (r *Abort) Finalize(chan<- tss.ParsedMessage) (Session, error) { return r, nil }
func (Abort) MessageContent() Content                               { return nil }
func (Abort) Number() Number                                        { return 0 }
func (r *Abort) CanFinalize() bool                                  { return false }
