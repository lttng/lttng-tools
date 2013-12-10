/*
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

import java.lang.Integer;
import java.util.logging.Logger;

import org.lttng.ust.jul.LTTngAgent;

public class JTestLTTng
{
	private static LTTngAgent lttngAgent;

	public static void main(String args[]) throws Exception
	{
		Logger lttng = Logger.getLogger("JTestLTTng");
		int nrIter = Integer.parseInt(args[0]);
		int waitTime = Integer.parseInt(args[1]);

		lttngAgent = LTTngAgent.getLTTngAgent();

		for (int iter = 0; iter < nrIter; iter++) {
			lttng.info("JUL tp fired!");
			Thread.sleep(waitTime);
		}

		lttngAgent.dispose();
	}
}
