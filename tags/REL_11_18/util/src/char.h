/**
 * Utilities for the quality of service module mod_qos.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2015 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

#define S_W_MAX 6
#define S_H_MAX 7

static int s_0[S_H_MAX][S_W_MAX] = {
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_1[S_H_MAX][S_W_MAX] = {
  { 0,0,0,1,0,0},
  { 0,0,1,1,0,0},
  { 0,1,0,1,0,0},
  { 0,0,0,1,0,0},
  { 0,0,0,1,0,0},
  { 0,0,0,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_2[S_H_MAX][S_W_MAX] = {
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 0,0,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0},
  { 1,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

static int s_3[S_H_MAX][S_W_MAX] = {
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 0,0,1,1,0,0},
  { 0,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_4[S_H_MAX][S_W_MAX] = {
  { 0,0,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0},
  { 1,0,0,1,0,0},
  { 1,1,1,1,1,0},
  { 0,0,0,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_5[S_H_MAX][S_W_MAX] = {
  { 1,1,1,1,1,0},
  { 1,0,0,0,0,0},
  { 1,1,1,1,0,0},
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0},
  { 1,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_6[S_H_MAX][S_W_MAX] = {
  { 0,1,1,1,0,0},
  { 1,0,0,0,0,0},
  { 1,0,1,1,0,0},
  { 1,1,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_7[S_H_MAX][S_W_MAX] = {
  { 1,1,1,1,1,0},
  { 0,0,0,0,1,0},
  { 0,0,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0},
  { 0,1,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_8[S_H_MAX][S_W_MAX] = {
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_9[S_H_MAX][S_W_MAX] = {
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

/* ----------------------------------------------- */
static int s_a[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

static int s_b[S_H_MAX][S_W_MAX] = {
  { 1,0,0,0,0,0},
  { 1,0,0,0,0,0},
  { 1,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_c[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,0,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_d[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

static int s_e[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,1,1,1,1,0},
  { 1,0,0,0,0,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_f[S_H_MAX][S_W_MAX] = {
  { 0,0,1,1,0,0},
  { 0,1,0,0,0,0},
  { 1,1,1,0,0,0},
  { 0,1,0,0,0,0},
  { 0,1,0,0,0,0},
  { 0,1,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_g[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,1,0},
  { 0,1,1,1,0,0}
};

static int s_h[S_H_MAX][S_W_MAX] = {
  { 1,0,0,0,0,0},
  { 1,0,0,0,0,0},
  { 1,0,1,1,0,0},
  { 1,1,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,0,0,0,0,0}
};

static int s_i[S_H_MAX][S_W_MAX] = {
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0},
  { 0,1,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_j[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,1,0},
  { 0,0,0,0,0,0},
  { 0,0,0,1,1,0},
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0},
  { 0,0,1,1,0,0}
};

static int s_k[S_H_MAX][S_W_MAX] = {
  { 1,0,0,0,0,0},
  { 1,0,0,0,0,0},
  { 1,0,1,1,0,0},
  { 1,1,0,0,0,0},
  { 1,0,1,0,0,0},
  { 1,0,0,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_l[S_H_MAX][S_W_MAX] = {
  { 0,1,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_m[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,1,0,1,0,0},
  { 1,0,1,0,1,0},
  { 1,0,1,0,1,0},
  { 1,0,1,0,1,0},
  { 1,0,1,0,1,0},
  { 0,0,0,0,0,0}
};

static int s_n[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,1,1,0,0},
  { 1,1,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,0,0,0,0,0}
};

static int s_o[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_p[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,1,1,1,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,1,1,1,0,0},
  { 1,0,0,0,0,0},
  { 1,0,0,0,0,0}
};

static int s_q[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0}
};

static int s_r[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,1,1,0,0},
  { 1,1,0,0,1,0},
  { 1,0,0,0,0,0},
  { 1,0,0,0,0,0},
  { 1,0,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_s[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,1,1,1,0},
  { 1,0,0,0,0,0},
  { 0,1,1,1,0,0},
  { 0,0,0,0,1,0},
  { 1,1,1,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_t[S_H_MAX][S_W_MAX] = {
  { 0,0,1,0,0,0},
  { 0,1,1,1,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,1,0},
  { 0,0,0,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_u[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

static int s_v[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_w[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,1,0,1,0},
  { 1,1,0,1,1,0},
  { 1,0,0,0,1,0},
  { 0,0,0,0,0,0}
};

static int s_x[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,0,0,1,0},
  { 0,1,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,1,0,0},
  { 1,0,0,0,1,0},
  { 0,0,0,0,0,0}
};

static int s_y[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,1,1,1,1,0},
  { 0,0,0,0,1,0},
  { 1,1,1,1,0,0}
};

static int s_z[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 1,1,1,1,1,0},
  { 0,0,0,1,1,0},
  { 0,0,1,0,0,0},
  { 1,1,0,0,0,0},
  { 1,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

static int s_BRO[S_H_MAX][S_W_MAX] = {
  { 0,0,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0},
  { 0,1,0,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_BRC[S_H_MAX][S_W_MAX] = {
  { 0,0,1,0,0,0},
  { 0,0,0,1,0,0},
  { 0,0,0,0,1,0},
  { 0,0,0,0,1,0},
  { 0,0,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_MI[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 1,1,1,1,1,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_LT[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,1,0,0},
  { 0,1,1,0,0,0},
  { 1,0,0,0,0,0},
  { 0,1,1,0,0,0},
  { 0,0,0,1,0,0},
  { 0,0,0,0,0,0}
};

static int s_GT[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,1,0,0,0,0},
  { 0,0,1,1,0,0},
  { 0,0,0,0,1,0},
  { 0,0,1,1,0,0},
  { 0,1,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_SP[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_US[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 1,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

static int s_M[S_H_MAX][S_W_MAX] = {
  { 1,0,0,0,1,0},
  { 1,1,0,1,1,0},
  { 1,0,1,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 1,0,0,0,1,0},
  { 0,0,0,0,0,0}
};

static int s_DT[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,1,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_CM[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0}
};

static int s_SC[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0}
};

static int s_CO[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_SL[S_H_MAX][S_W_MAX] = {
  { 0,0,0,0,0,1},
  { 0,0,0,0,1,0},
  { 0,0,0,1,0,0},
  { 0,0,1,0,0,0},
  { 0,1,0,0,0,0},
  { 1,0,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_SQ[S_H_MAX][S_W_MAX] = {
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,1,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0},
  { 0,0,0,0,0,0}
};

static int s_X[S_H_MAX][S_W_MAX] = {
  { 1,1,1,1,1,0},
  { 1,1,1,1,1,0},
  { 1,1,1,1,1,0},
  { 1,1,1,1,1,0},
  { 1,1,1,1,1,0},
  { 1,1,1,1,1,0},
  { 0,0,0,0,0,0}
};

