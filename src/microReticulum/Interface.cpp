/*
 * Copyright (c) 2023 Chad Attermann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

#include "Interface.h"

#include "Identity.h"
#include "Transport.h"
#include "Reticulum.h"
#include "Cryptography/HKDF.h"

#include <string.h>

using namespace RNS;
using namespace RNS::Type::Interface;

/*static*/ uint8_t Interface::DISCOVER_PATHS_FOR = MODE_ACCESS_POINT | MODE_GATEWAY | MODE_ROAMING;

// Ported from the IFAC implementation of RTNode-HeltecV4's microReticulum
// copy (Apache-2.0), itself following Python RNS Reticulum._add_interface():
// ifac_key = HKDF(64, SHA256(SHA256(netname) || SHA256(netkey)), IFAC_SALT),
// used both as a signing identity and as the mask salt.
void Interface::setup_ifac(const char* ifac_netname, const char* ifac_netkey) {
	assert(_impl);
	bool has_netname = (ifac_netname != nullptr && ifac_netname[0] != '\0');
	bool has_netkey = (ifac_netkey != nullptr && ifac_netkey[0] != '\0');
	if (!has_netname && !has_netkey) {
		_impl->_ifac_identity = {Bytes::NONE};
		_impl->_ifac_key = {Bytes::NONE};
		_impl->_ifac_id = {Type::NONE};
		return;
	}

	Bytes ifac_origin;
	if (has_netname) {
		ifac_origin += Identity::full_hash(Bytes((const uint8_t*)ifac_netname, strlen(ifac_netname)));
	}
	if (has_netkey) {
		ifac_origin += Identity::full_hash(Bytes((const uint8_t*)ifac_netkey, strlen(ifac_netkey)));
	}
	Bytes ifac_origin_hash = Identity::full_hash(ifac_origin);
	_impl->_ifac_key = Cryptography::hkdf(64, ifac_origin_hash, Bytes(IFAC_SALT, IFAC_SALT_SIZE));

	Identity ifac_id(false);
	ifac_id.load_private_key(_impl->_ifac_key);
	_impl->_ifac_id = ifac_id;
	// Non-empty = IFAC on (Transport tests it with operator bool).
	_impl->_ifac_identity = ifac_id.get_public_key();
	DEBUGF("Interface::setup_ifac: IFAC enabled on %s, ifac_size=%d", _impl->_name.c_str(), _impl->_ifac_size);
}

void InterfaceImpl::handle_outgoing(const Bytes& data) {
	//TRACEF("InterfaceImpl.handle_outgoing: data: %s", data.toHex().c_str());
	//TRACE("InterfaceImpl.handle_outgoing");
	_tx += 1;
	_txbytes += data.size();
}

void InterfaceImpl::handle_incoming(const Bytes& data) {
	//TRACEF("InterfaceImpl.handle_incoming: data: %s", data.toHex().c_str());
	//TRACE("InterfaceImpl.handle_incoming");
	_rx += 1;
	_rxbytes += data.size();
	// Create temporary Interface encapsulating our own shared impl
	std::shared_ptr<InterfaceImpl> self = shared_from_this();
	Interface interface(self);
	// Pass data on to transport for handling
	Transport::inbound(data, interface);
}

bool Interface::send_outgoing(const Bytes& data) {
	assert(_impl);
	//TRACEF("Interface.send_outgoing: data: %s", data.toHex().c_str());
	//TRACE("Interface.send_outgoing");
	// Catch exceptions from calls into Interface implementation
	try {
		return _impl->send_outgoing(data);
    }
    catch (const std::bad_alloc&) {
		ERROR("Interface::send_outgoing: bad_alloc - OUT OF MEMORY");
		// Critical OOM, restarting
#if defined(ESP32)
		ESP.restart();
#elif defined(ARDUINO_ARCH_NRF52) || defined(ARDUINO_NRF52_ADAFRUIT)
		NVIC_SystemReset();
#endif
    }
    catch (const std::exception& e) {
		ERRORF("Interface::send_outgoing: %s", e.what());
    }
	return false;
}

void Interface::handle_incoming(const Bytes& data) {
	assert(_impl);
	//TRACEF("Interface.handle_incoming: data: %s", data.toHex().c_str());
	//TRACE("Interface.handle_incoming");
	// Catch exceptions from calls into Interface implementation
	try {
		_impl->handle_incoming(data);
    }
    catch (const std::bad_alloc&) {
		ERROR("Interface::handle_incoming: bad_alloc - OUT OF MEMORY");
		// Critical OOM, restarting
#if defined(ESP32)
		ESP.restart();
#elif defined(ARDUINO_ARCH_NRF52) || defined(ARDUINO_NRF52_ADAFRUIT)
		NVIC_SystemReset();
#endif
    }
    catch (const std::exception& e) {
		ERRORF("Interface::handle_incoming: %s", e.what());
    }
}

void Interface::process_announce_queue() {
/*
	if not hasattr(self, "announce_cap"):
		self.announce_cap = RNS.Reticulum.ANNOUNCE_CAP

	if hasattr(self, "announce_queue"):
		try:
			now = time.time()
			stale = []
			for a in self.announce_queue:
				if now > a["time"]+RNS.Reticulum.QUEUED_ANNOUNCE_LIFE:
					stale.append(a)

			for s in stale:
				if s in self.announce_queue:
					self.announce_queue.remove(s)

			if len(self.announce_queue) > 0:
				min_hops = min(entry["hops"] for entry in self.announce_queue)
				entries = list(filter(lambda e: e["hops"] == min_hops, self.announce_queue))
				entries.sort(key=lambda e: e["time"])
				selected = entries[0]

				double now = OS::time();
				uint32_t wait_time = 0;
				if (_impl->_bitrate > 0 && _impl->_announce_cap > 0) {
					uint32_t tx_time = (len(selected["raw"])*8) / _impl->_bitrate;
					wait_time = (tx_time / _impl->_announce_cap);
				}
				_impl->_announce_allowed_at = now + wait_time;

				self.on_outgoing(selected["raw"])

				if selected in self.announce_queue:
					self.announce_queue.remove(selected)

				if len(self.announce_queue) > 0:
					timer = threading.Timer(wait_time, self.process_announce_queue)
					timer.start()

		except Exception as e:
			self.announce_queue = []
			RNS.log("Error while processing announce queue on "+str(self)+". The contained exception was: "+str(e), RNS.LOG_ERROR)
			RNS.log("The announce queue for this interface has been cleared.", RNS.LOG_ERROR)
*/
}

/*
void ArduinoJson::convertFromJson(JsonVariantConst src, RNS::Interface& dst) {
	TRACE(">>> Deserializing Interface");
TRACEF(">>> Interface pre: %s", dst.debugString().c_str());
	if (!src.isNull()) {
		RNS::Bytes hash;
		hash.assignHex(src.as<const char*>());
		TRACEF(">>> Querying Transport for Interface hash %s", hash.toHex().c_str());
		// Query transport for matching interface
		dst = Transport::find_interface_from_hash(hash);
TRACEF(">>> Interface post: %s", dst.debugString().c_str());
	}
	else {
		dst = {RNS::Type::NONE};
TRACEF(">>> Interface post: %s", dst.debugString().c_str());
	}
}
*/
