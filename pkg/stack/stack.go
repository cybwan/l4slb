package stack

type (
	Stack struct {
		top    *node
		bot    *node
		length int
	}
	node struct {
		value interface{}
		prev  *node
		next  *node
	}
)

// Create a new stack
func New() *Stack {
	return &Stack{nil, nil, 0}
}

// Return the number of items in the stack
func (this *Stack) Len() int {
	return this.length
}

// PopBack the top item of the stack and return it
func (this *Stack) PopBack() interface{} {
	if this.length == 0 {
		return nil
	}

	n := this.top
	this.top = n.prev
	if this.top != nil {
		this.top.next = nil
	}
	this.length--
	return n.value
}

// PushBack a value onto the top of the stack
func (this *Stack) PushBack(value interface{}) {
	n := &node{value: value}
	if this.length == 0 {
		this.top = n
		this.bot = n
	} else {
		this.top.next = n
		n.prev = this.top
		this.top = n
	}
	this.length++
}

// PopFront the bottom item of the stack and return it
func (this *Stack) PopFront() interface{} {
	if this.length == 0 {
		return nil
	}

	n := this.bot
	this.bot = n.next
	if this.bot != nil {
		this.bot.prev = nil
	}
	this.length--
	return n.value
}

// PushFront a value onto the bottom of the stack
func (this *Stack) PushFront(value interface{}) {
	n := &node{value: value}
	if this.length == 0 {
		this.top = n
		this.bot = n
	} else {
		this.bot.prev = n
		n.next = this.bot
		this.bot = n
	}
	this.length++
}
