/*
 * Copyright (C) 2015 - Michael Jeanson <mjeanson@efficios.com>
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

import java.io.IOException;
import java.lang.Integer;
import java.util.logging.Handler;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.lttng.ust.agent.jul.LttngLogHandler;

public class JTestLTTng {

	/**
	 * Application start
	 *
	 * @param args
	 *            Command-line arguments
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public static void main(String args[]) throws IOException, InterruptedException {

		Logger lttng = Logger.getLogger("JTestLTTng");
		Logger lttng2 = Logger.getLogger("JTestLTTng2");

		int nrIter = Integer.parseInt(args[0]);
		int waitTime = Integer.parseInt(args[1]);
		int fire_finest_tp = 0;
		int fire_second_tp = 0;

		if (args.length > 2) {
			fire_finest_tp = Integer.parseInt(args[2]);
		}
		if (args.length > 3) {
			fire_second_tp = Integer.parseInt(args[3]);
		}

		/* Instantiate a LTTngLogHandler object, and attach it to our loggers */
		Handler lttngHandler = new LttngLogHandler();
		lttng.addHandler(lttngHandler);
		lttng2.addHandler(lttngHandler);

		lttng.setLevel(Level.FINEST);

		for (int iter = 0; iter < nrIter; iter++) {
			lttng.info("JUL tp fired!");
			if (fire_finest_tp == 1) {
				/* Third arg, trigger finest TP. */
				lttng.finest("JUL FINEST tp fired");
			}
			Thread.sleep(waitTime);
		}

		if (fire_second_tp == 1) {
			lttng2.info("JUL second logger fired");
		}

		/*
		 * Do not forget to close() all handlers so that the agent can shutdown
		 * and the session daemon socket gets cleaned up explicitly.
		 */
		lttngHandler.close();
	}
}
