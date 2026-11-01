"use client";

import { useState } from "react";
import styles from "./animated-logo.module.css";

const innerRing = "M262.5 374.8A119 119 0 1 1 326.1 159.9M369.7 221.0A119 119 0 0 1 315.3 359.2";
const middleRing = "M256.4 439.0A183 183 0 0 1 86.2 324.2M73.0 256.4A183 183 0 0 1 124.6 128.6M175.4 91.7A183 183 0 0 1 369.0 112.0M405.7 150.7A183 183 0 0 1 358.0 407.9";
const outerRing = "M392.6 447.2A235 235 0 0 1 165.9 473.1M94.3 426.6A235 235 0 0 1 21.0 253.8M33.1 181.6A235 235 0 0 1 193.3 29.5M253.8 21.0A235 235 0 0 1 445.0 116.3M477.5 177.4A235 235 0 0 1 442.3 399.2";

/**
 * The Auth Platform mark. The three outer rings make one full turn, alternating direction, and
 * once they settle the centre resolves into a green check. Click it to replay.
 */
export function AnimatedLogo() {
  const [run, setRun] = useState(0);
  return (
    <button aria-label="Auth Platform logo. Activate to replay the animation." className={styles.stage} onClick={() => setRun((value) => value + 1)} type="button">
      <span className={styles.halo} key={`halo-${run}`} />
      <svg aria-hidden="true" className={styles.logo} fill="none" key={run} viewBox="0 0 512 512">
        <g className={styles.lines}>
          <path className={`${styles.ring} ${styles.outer}`} d={outerRing} />
          <path className={`${styles.ring} ${styles.middle}`} d={middleRing} />
          <path className={`${styles.ring} ${styles.inner}`} d={innerRing} />
          <circle className={styles.pulse} cx="256" cy="256" r="65" />
          <circle className={styles.core} cx="256" cy="256" r="65" />
          <circle className={styles.dot} cx="256" cy="256" r="7" />
          <path className={styles.check} d="M226 259 L243 274 L285 236" pathLength={1} />
        </g>
      </svg>
    </button>
  );
}
