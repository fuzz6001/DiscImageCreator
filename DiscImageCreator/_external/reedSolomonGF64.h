/**
 * Copyright 2025 sarami@ChatGPT
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

void cdg_rs6_init(void);
int cdg_check_packet_RS(const unsigned char pkt[24]);
int rs6_syndromes_highdeg(const uint8_t *code, int n, int m, uint8_t *S);
int rs6_q_correct(uint8_t code4[4]);
int rs6_p_correct(uint8_t code24[24]);
int rs6_p_correct_with_erasures(uint8_t code24[24], const int *eras, int e);
