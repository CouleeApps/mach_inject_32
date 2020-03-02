//
//  payload.cpp
//  payload
//
//  Created by Glenn Smith on 3/1/20.
//  Copyright © 2020 Plaintext. All rights reserved.
//

#include <AppKit/AppKit.h>

extern "C" {
	void inject();
}

void inject() {
	@autoreleasepool {
		NSAlert *alert = [NSAlert new];
		alert.informativeText = @"Alert!";
		[alert runModal];
	}
}
