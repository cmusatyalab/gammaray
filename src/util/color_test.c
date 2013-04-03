/*****************************************************************************
 * color_test.c                                                              *
 *                                                                           *
 * This file executes all of the colorized version of fprintf to test them.  *
 *                                                                           *
 *                                                                           *
 *   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                             *
 *                                                                           *
 *                                                                           *
 *   Copyright 2013 Carnegie Mellon University                               *
 *                                                                           *
 *   Licensed under the Apache License, Version 2.0 (the "License");         *
 *   you may not use this file except in compliance with the License.        *
 *   You may obtain a copy of the License at                                 *
 *                                                                           *
 *       http://www.apache.org/licenses/LICENSE-2.0                          *
 *                                                                           *
 *   Unless required by applicable law or agreed to in writing, software     *
 *   distributed under the License is distributed on an "AS IS" BASIS,       *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.*
 *   See the License for the specific language governing permissions and     *
 *   limitations under the License.                                          *
 *****************************************************************************/
#include "color.h"

#include <stdlib.h>

int main(int argc, char* argv[])
{
    fprintf_black(stdout, "fprintf_black\n");
    fprintf_red(stdout, "fprintf_red\n");
    fprintf_blue(stdout, "fprintf_blue\n");
    fprintf_green(stdout, "fprintf_green\n");
    fprintf_yellow(stdout, "fprintf_yellow\n");
    fprintf_magenta(stdout, "fprintf_magenta\n");
    fprintf_cyan(stdout, "fprintf_cyan\n");
    fprintf_white(stdout, "fprintf_white\n");

    fprintf_light_black(stdout, "fprintf_light_black\n");
    fprintf_light_red(stdout, "fprintf_light_red\n");
    fprintf_light_blue(stdout, "fprintf_light_blue\n");
    fprintf_light_green(stdout, "fprintf_light_green\n");
    fprintf_light_yellow(stdout, "fprintf_light_yellow\n");
    fprintf_light_magenta(stdout, "fprintf_light_magenta\n");
    fprintf_light_cyan(stdout, "fprintf_light_cyan\n");
    fprintf_light_white(stdout, "fprintf_light_white\n");

    return EXIT_SUCCESS;
}
