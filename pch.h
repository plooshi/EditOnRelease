// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"
#include "plooshfinder/include/formats/pe.h"
#include "plooshfinder/include/plooshfinder8.h"
#include "plooshfinder/include/plooshfinder.h"
#include <array>
#include <string>

enum EActivationMethod {
	CommandLine,
	F6,
	Both
};

#endif //PCH_H
