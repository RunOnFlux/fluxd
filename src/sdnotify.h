// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SDNOTIFY_H
#define BITCOIN_SDNOTIFY_H

#include <string>

/**
 * Readiness and status notifications to a supervising systemd, as sd_notify(3)
 * defines them, without libsystemd. A supervisor exists when NOTIFY_SOCKET is
 * set; otherwise every call is a no-op, so a fluxd run by hand, by pm2 or by a
 * Type=forking unit behaves as before.
 */

/** Whether NOTIFY_SOCKET names a supervisor to report to. */
bool SystemdNotifyEnabled();

/** Send one state line ("READY=1", "STOPPING=1", "STATUS=...") to the
 *  supervisor. False when there is none or the send failed; never throws. */
bool SystemdNotify(const std::string& state);

/** Send `state` to the datagram socket at `socketPath` ("@..." is the abstract
 *  namespace). False when the send failed. */
bool SystemdNotifyTo(const std::string& socketPath, const std::string& state);

/** Report an init-phase message as the unit's STATUS line. */
void SystemdNotifyStatus(const std::string& status);

#endif // BITCOIN_SDNOTIFY_H
