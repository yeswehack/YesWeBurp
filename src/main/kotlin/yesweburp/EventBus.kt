package yesweburp


class EventBus<T> {
    private val callbacks = mutableListOf<Pair<Boolean, (T) -> Unit>>()

    fun listen(cb: (T) -> Unit) {
        callbacks.add(Pair(true, cb))
    }

    fun listenOnce(cb: (T) -> Unit){
        callbacks.add(Pair(false, cb))
    }

    fun fire(data: T) {
        callbacks.retainAll {
            it.second(data)
            it.first
        }
    }
}
