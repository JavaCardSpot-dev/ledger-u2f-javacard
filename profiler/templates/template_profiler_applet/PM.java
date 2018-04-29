package com.ledger.u2f;

import javacard.framework.ISOException;

/**
 * Utility class for performance profiling. Contains currently set trap stop and trap reaction method. 
 * @author Petr Svenda
 */
public class PM {
    public static short m_perfStop = -1; // Performace measurement stop indicator

    // if m_perfStop equals to stopCondition, exception is throws (trap hit)
    public static void check(short stopCondition) { 
        if (PM.m_perfStop == stopCondition) {
            ISOException.throwIt(stopCondition);
        }
    }

}
