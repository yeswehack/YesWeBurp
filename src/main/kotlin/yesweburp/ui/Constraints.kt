package yesweburp.ui

import java.awt.GridBagConstraints
import java.awt.Insets

class Constraints(
    gridX: Int = RELATIVE,
    gridY: Int = RELATIVE,
    gridWidth: Int = 1,
    gridHeight: Int = 1,
    weightX: Double = 0.0,
    weightY: Double = 0.0,
    anchor: Int = CENTER,
    fill: Int = NONE,
    insets: Insets = Insets(0, 0, 0, 0),
    ipadX: Int = 0,
    ipadY: Int = 0
) : GridBagConstraints(gridX, gridY, gridWidth, gridHeight, weightX, weightY, anchor, fill, insets, ipadX, ipadY)