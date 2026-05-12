// aidblock 1.4.0: empty baseline test.
// 1.0.0/1.1.0/1.2.0/1.3.0 ALL safe-moded SpringBoard.
// Strip the tweak to only %ctor + NSLog. If THIS still safe-modes,
// the tweak injection itself is broken on this device (build error,
// wrong filter, code-sign issue, etc.) — not our hook code.
//
// If 1.4.0 loads cleanly without safe-mode, we know baseline works
// and we can iterate on hook code from a known-good starting point.

#import <Foundation/Foundation.h>

%ctor {
    NSLog(@"[aidblock] 1.4.0 baseline: loaded into pid=%d", getpid());
}
