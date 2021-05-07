package yesweburp.ui

import java.awt.Component
import java.awt.Dimension

fun matchSizes(first: Component, second: Component){
    val minWidth = maxOf(first.preferredSize.width, second.preferredSize.width)
    val minHeight = maxOf(first.preferredSize.height, second.preferredSize.height)
    val minDim = Dimension(minWidth, minHeight)
    first.minimumSize = minDim
    second.minimumSize = minDim
}


