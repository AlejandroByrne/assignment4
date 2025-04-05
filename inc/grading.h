/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

#ifndef UTCS356_ASSN4_INC_GRADING_H_
#define UTCS356_ASSN4_INC_GRADING_H_

/*
 * DO NOT CHANGE THIS FILE
 * This contains the variables for your TCP implementation
 * and we will replace this file during the autolab testing with new variables.
 */

// packet lengths
#define MAX_LEN 1400

// window variables
#define WINDOW_INITIAL_WINDOW_SIZE MSS
#define WINDOW_INITIAL_SSTHRESH (MSS * 64)

// retransmission timeout
#define DEFAULT_TIMEOUT 200  // ms

// max TCP buffer
#define MAX_NETWORK_BUFFER 65535  // (2^16 - 1) bytes

#endif  // UTCS356_ASSN4_INC_GRADING_H_
