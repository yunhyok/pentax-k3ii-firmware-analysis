/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>

/* Reference semantics. The firmware entry also preserves r3 and r12. */
uint16_t tone_interpolate(void *context, const uint16_t *curve, uint32_t sample)
{
    uint32_t index = sample >> 6;
    (void)context;

    if (index >= 255u)
        return curve[255];

    int32_t first = curve[index];
    int32_t delta = (int32_t)curve[index + 1u] - first;
    int32_t fraction = (int32_t)(sample & 63u);
    return (uint16_t)(first + (delta * fraction) / 64);
}

