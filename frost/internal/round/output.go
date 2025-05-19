package round

import "github.com/xlabs/tss-lib/v2/tss"

// Output is an empty round containing the output of the protocol.
type Output struct {
	*Helper
	Result interface{}
}

func (Output) VerifyMessage(Message) error                           { return nil }
func (Output) StoreMessage(Message) error                            { return nil }
func (r *Output) Finalize(chan<- tss.ParsedMessage) (Session, error) { return r, nil }
func (Output) MessageContent() Content                               { return nil }
func (Output) Number() Number                                        { return 0 }
func (r *Output) CanFinalize() bool                                  { return true }
