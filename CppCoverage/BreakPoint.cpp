// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2014 OpenCppCoverage
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "stdafx.h"
#include "BreakPoint.hpp"

#include "CppCoverageException.hpp"
#include "Address.hpp"

#include "Tools/Log.hpp"
#include "Tools/ProcessMemory.hpp"

namespace CppCoverage
{
	using Addresses = std::vector<DWORD64>;
	using AddressesIt = Addresses::const_iterator;

	//-------------------------------------------------------------------------
	bool LooksLikeSwitchTableData(HANDLE hProcess, void* address)
	{
		MEMORY_BASIC_INFORMATION memoryInfo{};
		if (VirtualQueryEx(hProcess, address, &memoryInfo, sizeof(memoryInfo)) == 0)
			return false;

		std::vector<unsigned char> bytes;
		try
		{
			bytes = Tools::ReadProcessMemory(hProcess, address, 8);
		}
		catch (...)
		{
			return false;
		}

		const auto isPlausibleCodeRva = [&](DWORD value) {
			return value >= 0x1000 && value < memoryInfo.RegionSize;
		};
		const auto rvaAt = [&](size_t offset) {
			return static_cast<DWORD>(bytes[offset]) |
			       (static_cast<DWORD>(bytes[offset + 1]) << 8) |
			       (static_cast<DWORD>(bytes[offset + 2]) << 16) |
			       (static_cast<DWORD>(bytes[offset + 3]) << 24);
		};

		// x64 MSVC emits switch jump tables as consecutive 4-byte RVAs inside
		// .text. DIA can map a source line to one of these entries; patching
		// 0xCC there changes the jump target and crashes the debuggee.
		if (isPlausibleCodeRva(rvaAt(0)) && isPlausibleCodeRva(rvaAt(4)))
			return true;

		// Small switch index tables are consecutive one-byte values.
		size_t smallByteCount = 0;
		for (const auto byte : bytes)
			if (byte <= 0x20)
				++smallByteCount;
		return smallByteCount >= 7;
	}

	//-------------------------------------------------------------------------
	void SetBreakPointsRange(HANDLE hProcess,
	                         AddressesIt begin,
	                         AddressesIt end,
	                         BreakPoint::InstructionCollection& oldInstructions)
	{
		if (begin == end)
			return;

		// Write one byte per breakpoint. The previous bulk write patched the
		// whole span between the first and last address of a 4K chunk; when a
		// line address pointed at data (e.g. a switch jump table in .text),
		// rewriting the surrounding bytes corrupted the data and crashed the
		// target process with 0xC0000005.
		unsigned char breakPoint = BreakPoint::breakPointInstruction;
		for (auto it = begin; it != end; ++it)
		{
			auto address = reinterpret_cast<void*>(*it);
			if (LooksLikeSwitchTableData(hProcess, address))
				continue;
			auto oldInstruction = Tools::ReadProcessMemory(hProcess, address, 1);
			oldInstructions.emplace_back(oldInstruction[0], *it);
			Tools::WriteProcessMemory(hProcess, address, &breakPoint, 1);
		}
	}

	const unsigned char BreakPoint::breakPointInstruction = 0xCC;

	//-------------------------------------------------------------------------
	BreakPoint::InstructionCollection
	BreakPoint::SetBreakPoints(HANDLE hProcess, Addresses&& addresses) const
	{
		InstructionCollection oldInstructions;

		std::sort(addresses.begin(), addresses.end());
		// Several source lines can map to the same address. Keeping duplicates
		// would record 0xCC as the "old" instruction for the second entry and
		// leave a live breakpoint behind after the first one is removed.
		addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
		auto beginRange = addresses.cbegin();

		for (auto it = beginRange; it < addresses.cend(); ++it)
		{
			if (*it - *beginRange > 4096)
			{
				SetBreakPointsRange(hProcess, beginRange, it, oldInstructions);
				beginRange = it;
			}
		}
		SetBreakPointsRange(
		    hProcess, beginRange, addresses.end(), oldInstructions);

		return oldInstructions;
	}

	//-------------------------------------------------------------------------
	void BreakPoint::RemoveBreakPoint(const Address& address,
	                                  unsigned char oldInstruction) const
	{
		Tools::WriteProcessMemory(address.GetProcessHandle(),
		                          address.GetValue(),
		                          &oldInstruction,
		                          sizeof(oldInstruction));
	}

	//-------------------------------------------------------------------------
	void BreakPoint::AdjustEipAfterBreakPointRemoval(HANDLE hThread) const
	{
		CONTEXT lcContext;
		lcContext.ContextFlags = CONTEXT_ALL;
		if (!GetThreadContext(hThread, &lcContext))
			THROW_LAST_ERROR("Error in GetThreadContext", GetLastError());

#ifdef _WIN64
		--lcContext.Rip; // Move back one byte
#else
		--lcContext.Eip; // Move back one byte
#endif
		if (!SetThreadContext(hThread, &lcContext))
			THROW_LAST_ERROR("Error in SetThreadContext", GetLastError());
	}
}
