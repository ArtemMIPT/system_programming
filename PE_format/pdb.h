#pragma once

#include <windows.h>

// CodeView header
struct CV_HEADER
{
	DWORD CvSignature; // NBxx
	LONG  Offset;      // Always 0 for NB10
};

// CodeView NB10 debug information of a PDB 2.00 file (VS 6)
typedef struct CV_INFO_PDB20
{
	CV_HEADER  CvHeader;
	DWORD      Signature;
	DWORD      Age;
	BYTE       PdbFileName[1];
} CV_INFO_PDB20, *PCV_INFO_PDB20;

// CodeView RSDS debug information of a PDB 7.00 file
typedef struct CV_INFO_PDB70
{
	DWORD      CvSignature;
	GUID       Signature;
	DWORD      Age;
	BYTE       PdbFileName[1];
} CV_INFO_PDB70, *PCV_INFO_PDB70;