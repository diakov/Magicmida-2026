unit Dumper;

// Magicmida 2026 v0.2d CRASH-TRACE
// Based on v0.2c.
// Keeps .pdata sorting, stale Security Directory cleanup and IAT tracing.
// After the dump is fully written and closed, launches the unpacked EXE under
// DEBUG_ONLY_THIS_PROCESS and records first/second-chance exceptions plus x64 context.
// Diagnostic build only; it does not patch the crash site.

interface

uses Windows, SysUtils, Classes, Generics.Collections, {$IFNDEF FPC}TlHelp32{$ELSE}JwaTlHelp32{$ENDIF},
     PEInfo, Utils{$IFNDEF FPC}, Math{$ENDIF};

const
  MAX_IAT_SIZE = 5120 * SizeOf(Pointer); // max 5K imports

type
  TExportTable = TDictionary<Pointer, string>;

  TForward = record
    Key: string;
    Value: Pointer;

    constructor Create(const AKey: string; AValue: Pointer);
  end;

  TRemoteModule = record
    Base, EndOff: PByte;
    Name: string;
    ExportTbl: TExportTable;
    Forwards: TList<TForward>;
  end;
  PRemoteModule = ^TRemoteModule;

  TForwardOrigin = record
    SourceModule: PRemoteModule;
    SourceAddress: Pointer;  // address in source module's export table

    constructor Create(ASourceModule: PRemoteModule; ASourceAddress: Pointer);
  end;

  TForwardMap = TObjectDictionary<Pointer, TList<TForwardOrigin>>;

  TImportThunk = class
  public
    Module: PRemoteModule;
    Name: string;
    Addresses: TList<PPointer>;

    constructor Create(RM: PRemoteModule);
    destructor Destroy; override;
  end;

  TOriginalImport = record
    DLLName: string;
    FuncName: string;
  end;

  TDumper = class
  private
    FProcess: TProcessInformation;
    FOEP, FIAT, FImageBase: NativeUInt;
    FForwards: TForwardMap;
    FAllModules: TList<PRemoteModule>;
    FIATImage: PByte;
    FIATImageSize: Cardinal;
    FOriginalImports: TList<TOriginalImport>;
    FUnresolvedOrdinalSlots: TList<Cardinal>;

    {$IFDEF CPUX86}
    FUsrPath: string;
    FHUsr: HMODULE;

    procedure CollectSpecialUser32Forwards(User32RM: PRemoteModule);
    {$ENDIF}

    procedure GatherModuleExportsFromRemoteProcess(M: PRemoteModule);
    procedure ResolveForwards(M: PRemoteModule);
    procedure TakeModuleSnapshot;
    function GetRemoteModule(const Name: string): PRemoteModule; overload;
    function GetRemoteModule(Base: HMODULE): PRemoteModule; overload;
    function RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
    procedure MakeMemoryReadable(Base, Size: NativeUInt);
    function GetOriginalImports(const FileName: string): TList<TOriginalImport>;
    function HasOriginalImport(const DLL, Func: string): Boolean;
  public
    constructor Create(const AProcess: TProcessInformation; const AOriginalFile: string; AImageBase, AOEP: UIntPtr);
    destructor Destroy; override;

    function Process: TPEHeader;
    procedure DumpToFile(const FileName: string; PE: TPEHeader; IsDLL: Boolean = False);

    function DetermineIATSize(IAT: PByte): UInt32;
    function IsAPIAddress(Address: NativeUInt): Boolean;

    class procedure SwitchSxSManifestType(S: TStream; PE: TPEHeader; SwitchFrom, SwitchTo: Integer);

    property IAT: NativeUInt read FIAT write FIAT; // Virtual address of IAT in target
  end;

  TDumperDotnet = class
  private
    FProcess: TProcessInformation;
    FImageBase: UIntPtr;
  public
    constructor Create(const AProcess: TProcessInformation; AImageBase: UIntPtr);

    procedure DumpToFile(const FileName: string);
  end;

implementation

uses OneCoreUAP;

type
  // PE2026 diagnostic helper. Pointer-sized fields keep this compatible
  // with both Win32 and Win64 builds.
  TImageTlsDirectoryNative = packed record
    StartAddressOfRawData: NativeUInt;
    EndAddressOfRawData: NativeUInt;
    AddressOfIndex: NativeUInt;
    AddressOfCallBacks: NativeUInt;
    SizeOfZeroFill: Cardinal;
    Characteristics: Cardinal;
  end;

  // x64 IMAGE_RUNTIME_FUNCTION_ENTRY / RUNTIME_FUNCTION.
  // The PE exception directory is an array of these 12-byte records.
  TRuntimeFunction2026 = packed record
    BeginAddress: Cardinal;
    EndAddress: Cardinal;
    UnwindInfoAddress: Cardinal;
  end;
  PRuntimeFunction2026 = ^TRuntimeFunction2026;

const
  ForwardPreferences: array[0..8] of string = (
    'kernel32.dll', // prioritize over kernelbase/ntdll
    'ole32.dll',    // prioritize over combase
    'advapi32.dll', // prioritize over cryptbase
    'netapi32.dll', // prioritize over netutils
    'comdlg32.dll', // prioritize over shlwapi
    'crypt32.dll',  // prioritize over dpapi
    'gdi32.dll',    // prioritize over gdi32full
    'dbghelp.dll',  // prioritize over dbgcore
    'setupapi.dll'  // prioritize over cfgmgr32
  );

function PreferenceScore(const Name: string): Integer;
var
  i: Integer;
begin
  Result := 0;
  for i := Low(ForwardPreferences) to High(ForwardPreferences) do
    if SameText(Name, ForwardPreferences[i]) then
      Inc(Result);
end;

{$IFDEF CPUX64}
procedure TraceCrash2026(const FileName: string);
const
  TRACE_TIMEOUT_MS = 15000;
var
  SI: TStartupInfo;
  PI: TProcessInformation;
  Ev: TDebugEvent;
  Status: DWORD;
  CmdLine, WorkDir: string;
  StartTick, NowTick: QWord;
  MainImageBase: NativeUInt;
  hThread: THandle;
  Ctx: TContext;
  CodeBuf: array[0..31] of Byte;
  BytesRead: SIZE_T;
  CodeHex: string;
  i: Integer;
  ExcCode: DWORD;
  ExcAddr: NativeUInt;
  FirstChance: Boolean;
  SawSecondChance: Boolean;
begin
  if not FileExists(FileName) then
  begin
    Log(ltFatal, '[CRASH2026] output file not found: ' + FileName);
    Exit;
  end;

  FillChar(SI, SizeOf(SI), 0);
  SI.cb := SizeOf(SI);
  FillChar(PI, SizeOf(PI), 0);

  CmdLine := '"' + FileName + '"';
  UniqueString(CmdLine);
  WorkDir := ExtractFilePath(FileName);
  if WorkDir = '' then
    WorkDir := GetCurrentDir;

  Log(ltInfo, '[CRASH2026] launching dumped EXE under debugger: ' + FileName);

  if not CreateProcess(
    nil,
    PChar(CmdLine),
    nil,
    nil,
    False,
    DEBUG_ONLY_THIS_PROCESS,
    nil,
    PChar(WorkDir),
    SI,
    PI) then
  begin
    Log(ltFatal, Format('[CRASH2026] CreateProcess failed: %d', [GetLastError]));
    Exit;
  end;

  MainImageBase := 0;
  SawSecondChance := False;
  StartTick := GetTickCount64;

  try
    while True do
    begin
      NowTick := GetTickCount64;
      if NowTick - StartTick >= TRACE_TIMEOUT_MS then
      begin
        Log(ltInfo, Format(
          '[CRASH2026] no second-chance crash within %d ms; terminating diagnostic run',
          [TRACE_TIMEOUT_MS]));
        TerminateProcess(PI.hProcess, $D1A60001);
        Break;
      end;

      if not WaitForDebugEvent(Ev, 250) then
      begin
        if GetLastError = ERROR_SEM_TIMEOUT then
          Continue;

        Log(ltFatal, Format(
          '[CRASH2026] WaitForDebugEvent failed: %d',
          [GetLastError]));
        Break;
      end;

      Status := DBG_CONTINUE;

      case Ev.dwDebugEventCode of
        CREATE_PROCESS_DEBUG_EVENT:
        begin
          MainImageBase := NativeUInt(Ev.CreateProcessInfo.lpBaseOfImage);
          Log(ltInfo, Format(
            '[CRASH2026] process started PID=%d imageBase=%X',
            [Ev.dwProcessId, MainImageBase]));

          if Ev.CreateProcessInfo.hFile <> 0 then
            CloseHandle(Ev.CreateProcessInfo.hFile);
        end;

        LOAD_DLL_DEBUG_EVENT:
        begin
          if Ev.LoadDll.hFile <> 0 then
            CloseHandle(Ev.LoadDll.hFile);
        end;

        EXCEPTION_DEBUG_EVENT:
        begin
          ExcCode := Ev.Exception.ExceptionRecord.ExceptionCode;
          ExcAddr := NativeUInt(Ev.Exception.ExceptionRecord.ExceptionAddress);
          FirstChance := Ev.Exception.dwFirstChance <> 0;

          // The loader's initial breakpoint is normal under a debugger.
          if (ExcCode = EXCEPTION_BREAKPOINT) and FirstChance then
          begin
            Log(ltInfo, Format(
              '[CRASH2026] initial breakpoint at %X',
              [ExcAddr]));
            Status := DBG_CONTINUE;
          end
          else
          begin
            if FirstChance then
              Log(ltInfo, Format(
                '[CRASH2026] first-chance exception code=%X address=%X',
                [ExcCode, ExcAddr]))
            else
              Log(ltFatal, Format(
                '[CRASH2026] SECOND-CHANCE exception code=%X address=%X',
                [ExcCode, ExcAddr]));

            if MainImageBase <> 0 then
            begin
              if ExcAddr >= MainImageBase then
                Log(ltInfo, Format(
                  '[CRASH2026] exception RVA=%X',
                  [ExcAddr - MainImageBase]))
              else
                Log(ltInfo, '[CRASH2026] exception address is outside main image');
            end;

            hThread := OpenThread(
              THREAD_GET_CONTEXT or THREAD_QUERY_INFORMATION,
              False,
              Ev.dwThreadId);

            if hThread <> 0 then
            begin
              try
                FillChar(Ctx, SizeOf(Ctx), 0);
                Ctx.ContextFlags := CONTEXT_FULL;

                if GetThreadContext(hThread, Ctx) then
                begin
                  Log(ltInfo, Format(
                    '[CRASH2026] RIP=%X RSP=%X RBP=%X',
                    [Ctx.Rip, Ctx.Rsp, Ctx.Rbp]));
                  Log(ltInfo, Format(
                    '[CRASH2026] RAX=%X RBX=%X RCX=%X RDX=%X',
                    [Ctx.Rax, Ctx.Rbx, Ctx.Rcx, Ctx.Rdx]));
                  Log(ltInfo, Format(
                    '[CRASH2026] RSI=%X RDI=%X R8=%X R9=%X',
                    [Ctx.Rsi, Ctx.Rdi, Ctx.R8, Ctx.R9]));
                  Log(ltInfo, Format(
                    '[CRASH2026] R10=%X R11=%X R12=%X R13=%X R14=%X R15=%X',
                    [Ctx.R10, Ctx.R11, Ctx.R12, Ctx.R13,
                     Ctx.R14, Ctx.R15]));
                end
                else
                  Log(ltInfo, Format(
                    '[CRASH2026] GetThreadContext failed: %d',
                    [GetLastError]));
              finally
                CloseHandle(hThread);
              end;
            end
            else
              Log(ltInfo, Format(
                '[CRASH2026] OpenThread failed: %d',
                [GetLastError]));

            FillChar(CodeBuf, SizeOf(CodeBuf), 0);
            BytesRead := 0;
            if ReadProcessMemory(
              PI.hProcess,
              Pointer(ExcAddr),
              @CodeBuf[0],
              SizeOf(CodeBuf),
              BytesRead) and (BytesRead <> 0) then
            begin
              CodeHex := '';
              for i := 0 to Integer(BytesRead) - 1 do
              begin
                if CodeHex <> '' then
                  CodeHex := CodeHex + ' ';
                CodeHex := CodeHex + IntToHex(CodeBuf[i], 2);
              end;

              Log(ltInfo, '[CRASH2026] bytes@exception: ' + CodeHex);
            end
            else
              Log(ltInfo, Format(
                '[CRASH2026] ReadProcessMemory at exception failed: %d',
                [GetLastError]));

            if (ExcCode = EXCEPTION_ACCESS_VIOLATION) and
               (Ev.Exception.ExceptionRecord.NumberParameters >= 2) then
            begin
              case Ev.Exception.ExceptionRecord.ExceptionInformation[0] of
                0: Log(ltInfo, Format(
                     '[CRASH2026] AV type=READ address=%X',
                     [Ev.Exception.ExceptionRecord.ExceptionInformation[1]]));
                1: Log(ltInfo, Format(
                     '[CRASH2026] AV type=WRITE address=%X',
                     [Ev.Exception.ExceptionRecord.ExceptionInformation[1]]));
                8: Log(ltInfo, Format(
                     '[CRASH2026] AV type=EXECUTE address=%X',
                     [Ev.Exception.ExceptionRecord.ExceptionInformation[1]]));
              else
                Log(ltInfo, Format(
                  '[CRASH2026] AV type=%d address=%X',
                  [Ev.Exception.ExceptionRecord.ExceptionInformation[0],
                   Ev.Exception.ExceptionRecord.ExceptionInformation[1]]));
              end;
            end;

            // Preserve normal Windows exception dispatch. First chance is offered
            // to the program; second chance is allowed to terminate it naturally.
            Status := DBG_EXCEPTION_NOT_HANDLED;

            if not FirstChance then
              SawSecondChance := True;
          end;
        end;

        EXIT_PROCESS_DEBUG_EVENT:
        begin
          Log(ltInfo, Format(
            '[CRASH2026] process exited code=%X secondChanceSeen=%d',
            [Ev.ExitProcess.dwExitCode, Ord(SawSecondChance)]));
          ContinueDebugEvent(Ev.dwProcessId, Ev.dwThreadId, DBG_CONTINUE);
          Break;
        end;
      end;

      if not ContinueDebugEvent(
        Ev.dwProcessId,
        Ev.dwThreadId,
        Status) then
      begin
        Log(ltFatal, Format(
          '[CRASH2026] ContinueDebugEvent failed: %d',
          [GetLastError]));
        Break;
      end;
    end;
  finally
    if PI.hThread <> 0 then
      CloseHandle(PI.hThread);
    if PI.hProcess <> 0 then
      CloseHandle(PI.hProcess);
  end;
end;
{$ENDIF}

{ TDumper }

constructor TDumper.Create(const AProcess: TProcessInformation; const AOriginalFile: string; AImageBase, AOEP: UIntPtr);
begin
  FProcess := AProcess;
  FOEP := AOEP;
  FImageBase := AImageBase;

  {$IFDEF CPUX86}
  if Win32MajorVersion > 5 then
  begin
    // user32 has an internal function 'PatchExportTableForwarders' that patches the AddressOfFunctions table.
    FUsrPath := ExtractFilePath(ParamStr(0)) + 'mmusr32.dll';
    CopyFile('C:\Windows\system32\user32.dll', PChar(FUsrPath), False);
    FHUsr := LoadLibraryEx(PChar(FUsrPath), 0, $20) - 2;
  end;
  {$ENDIF}

  FForwards := TForwardMap.Create([doOwnsValues], 512);
  FOriginalImports := GetOriginalImports(AOriginalFile);
  FUnresolvedOrdinalSlots := TList<Cardinal>.Create;
end;

destructor TDumper.Destroy;
var
  RM: PRemoteModule;
begin
  FForwards.Free;
  FOriginalImports.Free;
  FUnresolvedOrdinalSlots.Free;

  if FAllModules <> nil then
  begin
    for RM in FAllModules do
    begin
      RM.ExportTbl.Free;
      RM.Forwards.Free;
      Dispose(RM);
    end;
    FAllModules.Free;
  end;

  if FIATImage <> nil then
    FreeMem(FIATImage);

  {$IFDEF CPUX86}
  if FHUsr <> 0 then
  begin
    FreeLibrary(FHUsr + 2);
    Windows.DeleteFile(PChar(FUsrPath));
  end;
  {$ENDIF}

  inherited;
end;

{$POINTERMATH ON}

procedure TDumper.DumpToFile(const FileName: string; PE: TPEHeader; IsDLL: Boolean = False);
var
  FS: TFileStream;
  Buf: PByte;
  i: Integer;
  Size, Delta, IATRawOffset: Cardinal;
  TLS: TImageTlsDirectoryNative;
  TLSVA: NativeUInt;
  CallbackVA: NativeUInt;
  Callback: NativeUInt;
  CallbackIndex: Integer;
  {$IFDEF CPUX64}
  ExcRVA, ExcSize, ExcCount, ExcRemainder: Cardinal;
  ExcTable: PRuntimeFunction2026;
  ExcI, ExcJ, DisorderBefore, DisorderAfter: Integer;
  ExcTemp: TRuntimeFunction2026;
  TraceSlotListIndex: Integer;
  TraceSlotIndex: Cardinal;
  TraceSlotVA, TraceInstrVA, TraceTargetVA: NativeUInt;
  TracePos: Cardinal;
  TraceDisp: LongInt;
  TraceOp: string;
  TraceHits: Integer;
  TraceWindowStart, TraceWindowEnd, TraceK: Cardinal;
  TraceBytes: string;
  {$ENDIF}
begin
  FS := TFileStream.Create(FileName, fmCreate);
  try
    Size := PE.DumpSize;
    GetMem(Buf, Size);
    MakeMemoryReadable(FImageBase, Size);
    if not RPM(FImageBase, Buf, Size) then
      raise Exception.CreateFmt('DumpToFile RPM failed (base: %X, size: %X)', [FImageBase, Size]);

    IATRawOffset := FIAT - FImageBase;

    {$IFDEF CPUX64}
    // v0.2c IAT Trace:
    // Scan the dumped memory-layout image for common x64 RIP-relative
    // instructions that directly reference unresolved ordinal-only IAT slots.
    // This is diagnostic only: no instruction, slot or import is modified.
    if (FUnresolvedOrdinalSlots <> nil) and
       (FUnresolvedOrdinalSlots.Count <> 0) then
    begin
      Log(ltInfo, Format(
        '[IATTRACE] scanning image for references to %d unresolved ordinal slot(s)',
        [FUnresolvedOrdinalSlots.Count]));

      for TraceSlotListIndex := 0 to FUnresolvedOrdinalSlots.Count - 1 do
      begin
        TraceSlotIndex := FUnresolvedOrdinalSlots[TraceSlotListIndex];
        TraceSlotVA := FIAT + NativeUInt(TraceSlotIndex) * SizeOf(Pointer);
        TraceHits := 0;

        Log(ltInfo, Format(
          '[IATTRACE] slot index=%d VA=%X raw=%X ordinal=#%d',
          [TraceSlotIndex,
           TraceSlotVA,
           PNativeUInt(FIATImage + NativeUInt(TraceSlotIndex) * SizeOf(Pointer))^,
           Word(PNativeUInt(FIATImage + NativeUInt(TraceSlotIndex) * SizeOf(Pointer))^ and $FFFF)]));

        TracePos := 0;
        while TracePos + 7 <= Size do
        begin
          TraceOp := '';

          // CALL qword ptr [RIP+disp32] : FF 15 xx xx xx xx
          if (Buf[TracePos] = $FF) and (Buf[TracePos + 1] = $15) then
          begin
            Move(Buf[TracePos + 2], TraceDisp, SizeOf(TraceDisp));
            TraceInstrVA := FImageBase + TracePos;
            TraceTargetVA := TraceInstrVA + 6 + NativeInt(TraceDisp);
            TraceOp := 'CALL [RIP+disp32]';
          end
          // JMP qword ptr [RIP+disp32] : FF 25 xx xx xx xx
          else if (Buf[TracePos] = $FF) and (Buf[TracePos + 1] = $25) then
          begin
            Move(Buf[TracePos + 2], TraceDisp, SizeOf(TraceDisp));
            TraceInstrVA := FImageBase + TracePos;
            TraceTargetVA := TraceInstrVA + 6 + NativeInt(TraceDisp);
            TraceOp := 'JMP [RIP+disp32]';
          end
          // MOV/LEA r64,[RIP+disp32], including common REX prefixes 48/4C.
          else if ((Buf[TracePos] = $48) or (Buf[TracePos] = $4C)) and
                  ((Buf[TracePos + 1] = $8B) or (Buf[TracePos + 1] = $8D)) and
                  ((Buf[TracePos + 2] and $C7) = $05) then
          begin
            Move(Buf[TracePos + 3], TraceDisp, SizeOf(TraceDisp));
            TraceInstrVA := FImageBase + TracePos;
            TraceTargetVA := TraceInstrVA + 7 + NativeInt(TraceDisp);
            if Buf[TracePos + 1] = $8B then
              TraceOp := 'MOV reg,[RIP+disp32]'
            else
              TraceOp := 'LEA reg,[RIP+disp32]';
          end;

          if (TraceOp <> '') and (TraceTargetVA = TraceSlotVA) then
          begin
            Inc(TraceHits);

            if TracePos > 8 then
              TraceWindowStart := TracePos - 8
            else
              TraceWindowStart := 0;

            TraceWindowEnd := TracePos + 16;
            if TraceWindowEnd >= Size then
              TraceWindowEnd := Size - 1;

            TraceBytes := '';
            for TraceK := TraceWindowStart to TraceWindowEnd do
            begin
              if TraceBytes <> '' then
                TraceBytes := TraceBytes + ' ';
              TraceBytes := TraceBytes + IntToHex(Buf[TraceK], 2);
            end;

            Log(ltInfo, Format(
              '[IATTRACE]   HIT #%d instrVA=%X RVA=%X op=%s target=%X bytes=%s',
              [TraceHits,
               TraceInstrVA,
               TraceInstrVA - FImageBase,
               TraceOp,
               TraceTargetVA,
               TraceBytes]));
          end;

          Inc(TracePos);
        end;

        Log(ltInfo, Format(
          '[IATTRACE] slot index=%d totalDirectRefs=%d',
          [TraceSlotIndex, TraceHits]));
      end;
    end
    else
      Log(ltInfo, '[IATTRACE] no unresolved ordinal-only slots to trace');

    // v0.2b: validate and sort the x64 Exception Directory before any physical
    // trimming. At this stage Buf is a memory-layout image, so RVA == Buf offset.
    ExcRVA := PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    ExcSize := PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (ExcRVA <> 0) and (ExcSize >= SizeOf(TRuntimeFunction2026)) then
    begin
      ExcCount := ExcSize div SizeOf(TRuntimeFunction2026);
      ExcRemainder := ExcSize mod SizeOf(TRuntimeFunction2026);

      if (UInt64(ExcRVA) + UInt64(ExcCount) * SizeOf(TRuntimeFunction2026) <= UInt64(Size)) then
      begin
        ExcTable := PRuntimeFunction2026(Buf + ExcRVA);

        DisorderBefore := 0;
        for ExcI := 1 to Integer(ExcCount) - 1 do
          if ExcTable[ExcI].BeginAddress < ExcTable[ExcI - 1].BeginAddress then
          begin
            Inc(DisorderBefore);
            Log(ltInfo, Format(
              '[PDATA2026] out-of-order before sort: idx=%d prev=%X..%X cur=%X..%X unwind=%X',
              [ExcI,
               ExcTable[ExcI - 1].BeginAddress,
               ExcTable[ExcI - 1].EndAddress,
               ExcTable[ExcI].BeginAddress,
               ExcTable[ExcI].EndAddress,
               ExcTable[ExcI].UnwindInfoAddress]));
          end;

        Log(ltInfo, Format(
          '[PDATA2026] exception table RVA=%X Size=%X entries=%d remainder=%d disorderBefore=%d',
          [ExcRVA, ExcSize, ExcCount, ExcRemainder, DisorderBefore]));

        if DisorderBefore <> 0 then
        begin
          // Stable insertion sort. We only reorder complete RUNTIME_FUNCTION
          // records; Begin/End/UnwindInfo values themselves are never changed.
          for ExcI := 1 to Integer(ExcCount) - 1 do
          begin
            ExcTemp := ExcTable[ExcI];
            ExcJ := ExcI - 1;
            while (ExcJ >= 0) and
                  (ExcTable[ExcJ].BeginAddress > ExcTemp.BeginAddress) do
            begin
              ExcTable[ExcJ + 1] := ExcTable[ExcJ];
              Dec(ExcJ);
            end;
            ExcTable[ExcJ + 1] := ExcTemp;
          end;
        end;

        DisorderAfter := 0;
        for ExcI := 1 to Integer(ExcCount) - 1 do
          if ExcTable[ExcI].BeginAddress < ExcTable[ExcI - 1].BeginAddress then
            Inc(DisorderAfter);

        Log(ltInfo, Format(
          '[PDATA2026] sort complete: disorderAfter=%d changed=%d',
          [DisorderAfter, Ord(DisorderBefore <> 0)]));
      end
      else
        Log(ltFatal, Format(
          '[PDATA2026] exception directory outside dump buffer: RVA=%X Size=%X DumpSize=%X',
          [ExcRVA, ExcSize, Size]));
    end
    else
      Log(ltInfo, '[PDATA2026] exception directory absent or too small');
    {$ENDIF}

    // TrimHugeSections may adjust IATRawOffset depending on what is trimmed.
    Delta := PE.TrimHugeSections(Buf, IATRawOffset);
    Dec(Size, Delta);
    FS.Write(Buf^, Size);
    FreeMem(Buf);

    for i := PE.NTHeaders.FileHeader.NumberOfSections to High(PE.Sections) do
    begin
      FS.Write(PE.Sections[i].Data^, PE.Sections[i].Header.SizeOfRawData);
    end;
    PE.NTHeaders.FileHeader.NumberOfSections := Length(PE.Sections);
    PE.NTHeaders.OptionalHeader.AddressOfEntryPoint := FOEP - FImageBase;

    if IsDLL then
    begin
      PE.NTHeaders.FileHeader.Characteristics := PE.NTHeaders.FileHeader.Characteristics or IMAGE_FILE_DLL;

      SwitchSxSManifestType(FS, PE, 1, 2); // Switch back
    end;

    if (PE.NTHeaders.OptionalHeader.DllCharacteristics and $40) <> 0 then
    begin
      Log(ltInfo, 'Executable is ASLR-aware - disabling the flag in the dump');
      PE.NTHeaders.OptionalHeader.DllCharacteristics := PE.NTHeaders.OptionalHeader.DllCharacteristics and not $40;
    end;

    // 2026 diagnostics: these directories are especially important for modern x64
    // MSVC applications.  Do not silently clear or synthesize them here; report
    // what survived the unpacking so a bad dump can be diagnosed deterministically.
    with PE.NTHeaders.OptionalHeader do
    begin
      Log(ltInfo, Format('[PE2026] Exception dir: RVA=%X Size=%X',
        [DataDirectory[3].VirtualAddress, DataDirectory[3].Size]));
      Log(ltInfo, Format('[PE2026] TLS dir: RVA=%X Size=%X',
        [DataDirectory[9].VirtualAddress, DataDirectory[9].Size]));
      Log(ltInfo, Format('[PE2026] LoadConfig dir: RVA=%X Size=%X',
        [DataDirectory[10].VirtualAddress, DataDirectory[10].Size]));
      Log(ltInfo, Format('[PE2026] DelayImport dir: RVA=%X Size=%X',
        [DataDirectory[13].VirtualAddress, DataDirectory[13].Size]));
    end;

    // PE2026: inspect live TLS callback metadata. Diagnostic-only.
    if PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress <> 0 then
    begin
      TLSVA := FImageBase +
        PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

      FillChar(TLS, SizeOf(TLS), 0);
      if RPM(TLSVA, @TLS, SizeOf(TLS)) then
      begin
        Log(ltInfo, Format(
          '[TLS2026] directory VA=%X RawStart=%X RawEnd=%X Index=%X Callbacks=%X ZeroFill=%X Char=%X',
          [TLSVA,
           TLS.StartAddressOfRawData,
           TLS.EndAddressOfRawData,
           TLS.AddressOfIndex,
           TLS.AddressOfCallBacks,
           TLS.SizeOfZeroFill,
           TLS.Characteristics]));

        CallbackVA := TLS.AddressOfCallBacks;
        if CallbackVA = 0 then
          Log(ltInfo, '[TLS2026] AddressOfCallbacks = 0')
        else
        begin
          CallbackIndex := 0;
          while CallbackIndex < 32 do
          begin
            Callback := 0;
            if not RPM(
              CallbackVA + NativeUInt(CallbackIndex) * SizeOf(Pointer),
              @Callback,
              SizeOf(Callback)) then
            begin
              Log(ltInfo, Format(
                '[TLS2026] callback[%d] read failed at %X',
                [CallbackIndex,
                 CallbackVA + NativeUInt(CallbackIndex) * SizeOf(Pointer)]));
              Break;
            end;

            if Callback = 0 then
            begin
              Log(ltInfo, Format('[TLS2026] callback[%d] = NULL',
                [CallbackIndex]));
              Break;
            end;

            if Callback >= FImageBase then
              Log(ltInfo, Format(
                '[TLS2026] callback[%d] = %X (RVA=%X)',
                [CallbackIndex, Callback, Callback - FImageBase]))
            else
              Log(ltInfo, Format(
                '[TLS2026] callback[%d] = %X (outside image)',
                [CallbackIndex, Callback]));

            Inc(CallbackIndex);
          end;
        end;
      end
      else
        Log(ltInfo, Format(
          '[TLS2026] failed reading TLS directory at %X',
          [TLSVA]));
    end
    else
      Log(ltInfo, '[TLS2026] TLS directory absent');

    // v0.2b: Security Directory uses a FILE OFFSET, not an RVA. Any Authenticode
    // signature from the protected input is invalid after unpacking/rebuilding,
    // and its old file offset may now point into an ordinary section.
    with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] do
    begin
      if (VirtualAddress <> 0) or (Size <> 0) then
        Log(ltInfo, Format(
          '[SEC2026] clearing stale Security Directory: FileOffset=%X Size=%X',
          [VirtualAddress, Size]));
      VirtualAddress := 0;
      Size := 0;
    end;

    PE.SaveToStream(FS);

    FS.Seek(IATRawOffset, soBeginning);
    FS.Write(FIATImage^, FIATImageSize);
  finally
    FS.Free;
  end;

  {$IFDEF CPUX64}
  // v0.2d diagnostic run happens only after the reconstructed file is closed.
  TraceCrash2026(FileName);
  {$ENDIF}
end;

function TDumper.DetermineIATSize(IAT: PByte): UInt32;
var
  LastValidOffset, i: UInt32;
begin
  LastValidOffset := 0;
  i := 0;
  while (i < MAX_IAT_SIZE) and ((LastValidOffset = 0) or (i < LastValidOffset + $100)) do
  begin
    if IsAPIAddress(PNativeUInt(IAT + i)^) then
      LastValidOffset := i;

    Inc(i, SizeOf(Pointer));
  end;

  Result := LastValidOffset + SizeOf(Pointer);
end;

type
  TResolutionCandidate = record
    Address: Pointer;      // The pointer to use for export lookup
    Module: PRemoteModule;
  end;

  TIATSlot = record
    Candidates: TList<TResolutionCandidate>; // All valid resolutions
    ChosenCandidate: Integer;                // Index into Candidates (-1 = unresolved)
    IsZero: Boolean;
    IsEncodedOrdinal: Boolean;               // PE32/PE32+ IMAGE_ORDINAL_FLAG | ordinal
    EncodedOrdinal: Word;
  end;

function TDumper.Process: TPEHeader;
var
  IAT: PByte;
  i, j, k: Integer;
  IATSize, Diff: Cardinal;
  PE: TPEHeader;
  a: ^PByte;
  Thunks: TList<TImportThunk>;
  Thunk: TImportThunk;
  RM: PRemoteModule;
  s: AnsiString;
  OrdIndex: Cardinal;
  Section, Strs: PByte;
  Descriptors: PImageImportDescriptor;
  ImportSect: PPESection;
  AllowApiSets: Boolean;

  // --- Pass 1 data ---
  Slots: array of TIATSlot;
  Cand: TResolutionCandidate;
  SlotCount: Integer;
  Origins: TList<TForwardOrigin>;
  Origin: TForwardOrigin;

  // --- Pass 2 data ---
  GroupStart, GroupEnd: Integer;
  ModuleVotes: TDictionary<string, Integer>;
  ModuleName, WinnerName, FuncName, ApiSetName: string;
  WinnerVotes: Integer;
  WinnerRM: PRemoteModule;
  FuncAddr: Pointer;
  DiagIndex: Integer;
begin
  if FIAT = 0 then
    raise Exception.Create('Must set IAT before calling Process()');

  // Read header from memory
  GetMem(Section, $1000);
  RPM(FImageBase, Section, $1000);
  PE := TPEHeader.Create(Section);
  PE.Sanitize;
  FreeMem(Section);

  GetMem(IAT, MAX_IAT_SIZE);
  RPM(FIAT, IAT, MAX_IAT_SIZE);

  IATSize := DetermineIATSize(IAT);
  Log(ltInfo, Format('Determined IAT size: %X', [IATSize]));

  with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] do
  begin
    VirtualAddress := FIAT - FImageBase;
    Size := IATSize + SizeOf(Pointer);
  end;

  if FAllModules = nil then
    TakeModuleSnapshot;

  AllowApiSets := False;
  for i := 0 to FOriginalImports.Count - 1 do
    if Pos('api-ms-win', FOriginalImports[i].DLLName) = 1 then
    begin
      AllowApiSets := True;
      Break;
    end;

  SlotCount := IATSize div SizeOf(Pointer);
  SetLength(Slots, SlotCount);
  FUnresolvedOrdinalSlots.Clear;

  // =========================================================
  // PASS 1: Collect all candidates for every IAT slot
  // =========================================================
  a := Pointer(IAT);
  for i := 0 to SlotCount - 1 do
  begin
    Slots[i].ChosenCandidate := -1;
    Slots[i].Candidates := TList<TResolutionCandidate>.Create;
    Slots[i].IsZero := a^ = nil;
    Slots[i].IsEncodedOrdinal := (NativeUInt(a^) and NativeUInt(IMAGE_ORDINAL_FLAG)) <> 0;
    Slots[i].EncodedOrdinal := Word(NativeUInt(a^) and $FFFF);

    if Slots[i].IsZero then
    begin
      Inc(a);
      Continue;
    end;

    // --- Variant A: no forwarding ---
    Cand.Address := a^;
    Cand.Module := nil;
    for RM in FAllModules do
      if (PByte(Cand.Address) > RM.Base) and (PByte(Cand.Address) < RM.EndOff) then
      begin
        if RM.ExportTbl.ContainsKey(Cand.Address) then
        begin
          Cand.Module := RM;
          Slots[i].Candidates.Add(Cand);
        end;
        Break; // only one module owns this address
      end;

    // --- Variant B: FForwards (e.g. ntdll stub -> kernelbase real) ---
    if FForwards.TryGetValue(a^, Origins) then
      for Origin in Origins do
      begin
        Cand.Address := Origin.SourceAddress;
        Cand.Module := Origin.SourceModule;
        Slots[i].Candidates.Add(Cand);
      end;

    if Slots[i].Candidates.Count = 0 then
      Log(ltInfo, 'IAT slot ' + IntToHex(FIAT + Cardinal(i) * SizeOf(Pointer), 8) +
          ' -> ' + IntToHex(UIntPtr(a^), 8) + ' unresolvable');

    Inc(a);
  end;

  // =========================================================
  // PE2026: detailed diagnostics around unresolved ordinals
  // =========================================================
  for i := 0 to SlotCount - 1 do
  begin
    if Slots[i].IsEncodedOrdinal and
       (Slots[i].Candidates.Count = 0) then
    begin
      if FUnresolvedOrdinalSlots.IndexOf(Cardinal(i)) < 0 then
        FUnresolvedOrdinalSlots.Add(Cardinal(i));

      Log(ltInfo, Format(
        '[IAT2026] unresolved ordinal: index=%d VA=%X raw=%X ordinal=#%d',
        [i,
         FIAT + NativeUInt(i) * SizeOf(Pointer),
         PNativeUInt(IAT + NativeUInt(i) * SizeOf(Pointer))^,
         Slots[i].EncodedOrdinal]));

      j := i - 8;
      if j < 0 then
        j := 0;

      k := i + 8;
      if k >= SlotCount then
        k := SlotCount - 1;

      while j <= k do
      begin
        ModuleName := '';

        if Slots[j].Candidates.Count <> 0 then
        begin
          for DiagIndex := 0 to Slots[j].Candidates.Count - 1 do
          begin
            if ModuleName <> '' then
              ModuleName := ModuleName + ',';

            if Slots[j].Candidates[DiagIndex].Module <> nil then
              ModuleName := ModuleName +
                Slots[j].Candidates[DiagIndex].Module.Name
            else
              ModuleName := ModuleName + '<nil>';
          end;
        end
        else
          ModuleName := '-';

        Log(ltInfo, Format(
          '[IAT2026]   [%d] VA=%X raw=%X zero=%d encodedOrd=%d ord=#%d candidates=%s',
          [j,
           FIAT + NativeUInt(j) * SizeOf(Pointer),
           PNativeUInt(IAT + NativeUInt(j) * SizeOf(Pointer))^,
           Ord(Slots[j].IsZero),
           Ord(Slots[j].IsEncodedOrdinal),
           Slots[j].EncodedOrdinal,
           ModuleName]));

        Inc(j);
      end;
    end;
  end;

  // =========================================================
  // PASS 2: For each zero-delimited group, vote on best module
  //         and pin every slot to a candidate from that module
  // =========================================================
  ModuleVotes := TDictionary<string, Integer>.Create;
  Thunks := TObjectList<TImportThunk>.Create;

  i := 0;
  while i < SlotCount do
  begin
    // Skip zero separators (they just end the current thunk naturally)
    if Slots[i].IsZero then
    begin
      Inc(i);
      Continue;
    end;

    // Find contiguous non-zero run = one raw group
    GroupStart := i;
    GroupEnd := i;
    while (GroupEnd + 1 < SlotCount) and not Slots[GroupEnd + 1].IsZero do
      Inc(GroupEnd);

    // Vote: for each slot in group, each candidate casts one vote for its module
    ModuleVotes.Clear;
    for j := GroupStart to GroupEnd do
    begin
      //Log(ltInfo, Format('Slot %d (%p)', [j, PByte(IAT) + j * SizeOf(Pointer)]));
      for k := 0 to Slots[j].Candidates.Count - 1 do
      begin
        ModuleName := Slots[j].Candidates[k].Module.Name;
        //Log(ltInfo, Format(' - Candidate %s %p', [ModuleName, Slots[j].Candidates[k].Address]));
        if not ModuleVotes.TryGetValue(ModuleName, WinnerVotes) then
          ModuleVotes.Add(ModuleName, 1)
        else
          ModuleVotes[ModuleName] := WinnerVotes + 1;
      end;
    end;

    // Find the module with the most votes; apply scoring in ambiguous cases
    WinnerName := '';
    WinnerVotes := -1;
    WinnerRM := nil;
    for ModuleName in ModuleVotes.Keys do
    begin
      if (ModuleVotes[ModuleName] > WinnerVotes) or
         ((ModuleVotes[ModuleName] = WinnerVotes) and
          (PreferenceScore(ModuleName) > PreferenceScore(WinnerName))) then
      begin
        WinnerVotes := ModuleVotes[ModuleName];
        WinnerName := ModuleName;
      end;
    end;

    // PE2026: show why an ordinal-containing group did or did not
    // get a module winner.
    for j := GroupStart to GroupEnd do
      if Slots[j].IsEncodedOrdinal and
         (Slots[j].Candidates.Count = 0) then
      begin
        Log(ltInfo, Format(
          '[IAT2026] ordinal group: slots=%d..%d VA=%X..%X winner="%s" votes=%d',
          [GroupStart,
           GroupEnd,
           FIAT + NativeUInt(GroupStart) * SizeOf(Pointer),
           FIAT + NativeUInt(GroupEnd) * SizeOf(Pointer),
           WinnerName,
           WinnerVotes]));
        Break;
      end;

    // Pin each slot to the winning module's candidate
    for j := GroupStart to GroupEnd do
    begin
      for k := 0 to Slots[j].Candidates.Count - 1 do
        if Slots[j].Candidates[k].Module.Name = WinnerName then
        begin
          Slots[j].ChosenCandidate := k;
          if WinnerRM = nil then
            WinnerRM := Slots[j].Candidates[k].Module;
          Break;
        end;
    end;

    // Modern Themida builds may leave valid ordinal-encoded thunks in the IAT.
    // Older Magicmida treated 0x8000...|ordinal values as bogus because they are
    // not live API pointers.  Resolve them against the module selected by the
    // surrounding IAT group, but only when that module actually exports #ordinal.
    if WinnerRM <> nil then
      for j := GroupStart to GroupEnd do
        if (Slots[j].ChosenCandidate < 0) and Slots[j].IsEncodedOrdinal then
        begin
          FuncName := '#' + IntToStr(Slots[j].EncodedOrdinal);
          for FuncAddr in WinnerRM.ExportTbl.Keys do
            if WinnerRM.ExportTbl[FuncAddr] = FuncName then
            begin
              Cand.Address := FuncAddr;
              Cand.Module := WinnerRM;
              Slots[j].Candidates.Add(Cand);
              Slots[j].ChosenCandidate := Slots[j].Candidates.Count - 1;
              Log(ltInfo, Format('IAT slot %X: resolved ordinal %s in %s',
                [FIAT + Cardinal(j) * SizeOf(Pointer), FuncName, WinnerName]));
              Break;
            end;
        end;

    ApiSetName := '';
    if AllowApiSets then
      for j := GroupStart to GroupEnd do
      begin
        if (Slots[j].ChosenCandidate < 0) and (Slots[j].Candidates.Count = 0) then
          Continue;

        // If it had no candidate for WinnerRM, see if we can map it into the same apiset
        if Slots[j].ChosenCandidate < 0 then
          FuncName := Slots[j].Candidates[0].Module.ExportTbl[Slots[j].Candidates[0].Address]
        else
          FuncName := WinnerRM.ExportTbl[Slots[j].Candidates[Slots[j].ChosenCandidate].Address];

        if Pos('RtlQueryPerformance', FuncName) = 1 then
          Delete(FuncName, 1, 3); // Hack for api-ms-win-core-profile-l1-1-0.dll

        if j = GroupStart then
          ApiSetName := GetOneCoreUAPModuleByAPI(FuncName)
        else if (ApiSetName <> '') and (GetOneCoreUAPModuleByAPI(FuncName) <> ApiSetName) then
          ApiSetName := '';
      end;

    // If using an ApiSet, remap so the slot is not skipped as bogus. Looking for the same name
    // in WinnerRM is a bit risky, but so far this has happened between kernel32 and kernelbase.
    if ApiSetName <> '' then
      for j := GroupStart to GroupEnd do
        if Slots[j].ChosenCandidate < 0 then
        begin
          FuncName := Slots[j].Candidates[0].Module.ExportTbl[Slots[j].Candidates[0].Address];
          // Find the address of this function in WinnerRM's export table
          for FuncAddr in WinnerRM.ExportTbl.Keys do
            if WinnerRM.ExportTbl[FuncAddr] = FuncName then
            begin
              Slots[j].Candidates.{$IFNDEF FPC}PList^{$ELSE}List{$ENDIF}[0].Address := FuncAddr;
              Slots[j].ChosenCandidate := 0;
              Log(ltInfo, Format('IAT slot %X: remapped apiset member %s', [FIAT + Cardinal(j) * SizeOf(Pointer), FuncName]));
              Break;
            end;
        end;

    // Now walk the group and build thunks, respecting the chosen candidates.
    // Within a zero-free group we stay in one thunk for the winner module.
    Thunk := nil;
    for j := GroupStart to GroupEnd do
    begin
      if Slots[j].ChosenCandidate < 0 then
      begin
        Log(ltFatal, Format('IAT slot %X  has no candidate for winning module %s (bogus entry)', [FIAT + Cardinal(j) * SizeOf(Pointer), WinnerName]));
        Continue;
      end;

      if Thunk = nil then
      begin
        Thunk := TImportThunk.Create(WinnerRM);
        Thunk.Name := WinnerName;
        Thunks.Add(Thunk);
      end;

      // Write the resolved pointer back into the IAT image
      Cand := Slots[j].Candidates[Slots[j].ChosenCandidate];
      PPointer(PByte(IAT) + j * SizeOf(Pointer))^ := Cand.Address;
      Thunk.Addresses.Add(PPointer(PByte(IAT) + j * SizeOf(Pointer)));
    end;
    if (Thunk <> nil) and (ApiSetName <> '') and
       not HasOriginalImport(Thunk.Name, WinnerRM.ExportTbl[PPointer(PByte(IAT) + GroupStart * SizeOf(Pointer))^]) then
    begin
      Log(ltInfo, Format('OneCoreUAP: Using %s instead of %s', [ApiSetName, WinnerName]));
      Thunk.Name := ApiSetName;
    end;

    i := GroupEnd + 1;
  end;
  ModuleVotes.Free;

  ImportSect := PE.CreateSection('.import', $1000);

  Section := AllocMem(ImportSect.Header.SizeOfRawData);
  Pointer(Descriptors) := Section; // Map the Descriptors array to the start of the section
  Strs := Section + (Thunks.Count + 1) * SizeOf(TImageImportDescriptor); // Last descriptor is empty

  i := 0;
  for Thunk in Thunks do
  begin
    Descriptors[i].FirstThunk := (FIAT - FImageBase) + UIntPtr(Thunk.Addresses.First) - UIntPtr(IAT);
    Descriptors[i].Name := PE.ConvertOffsetToRVAVector(ImportSect.Header.PointerToRawData + Cardinal(Strs - Section));
    Inc(i);
    s := AnsiString(Thunk.Name);
    Move(s[1], Strs^, Length(s));
    Inc(Strs, Length(s) + 1);
    RM := Thunk.Module;
    Log(ltInfo, 'Thunk ' + Thunk.Name + ' - first import: ' + RM.ExportTbl[Thunk.Addresses.First^]);
    for j := 0 to Thunk.Addresses.Count - 1 do
    begin
      s := AnsiString(RM.ExportTbl[Thunk.Addresses[j]^]);
      if s[1] = '#' then
      begin
        OrdIndex := StrToInt(Copy(string(s), 2, 5));
        Thunk.Addresses[j]^ := Pointer(IMAGE_ORDINAL_FLAG or OrdIndex);
        Continue;
      end;
      if (Pos(AnsiString('RtlQueryPerformance'), s) = 1) and (Pos('api-ms-win', Thunk.Name) = 1) then
        Delete(s, 1, 3);

      Inc(Strs, 2); // Hint
      // Set the address in the IAT to this string entry
      Thunk.Addresses[j]^ := Pointer(PE.ConvertOffsetToRVAVector(ImportSect.Header.PointerToRawData + Cardinal(Strs - 2 - Section)));
      Move(s[1], Strs^, Length(s));
      Inc(Strs, Length(s) + 1);

      if Strs > Section + ImportSect.Header.SizeOfRawData - $100 then
      begin
        Inc(ImportSect.Header.SizeOfRawData, $1000);
        Inc(ImportSect.Header.Misc.VirtualSize, $1000);
        Inc(PE.NTHeaders.OptionalHeader.SizeOfImage, $1000);
        Diff := Strs - Section;
        ReallocMem(Section, ImportSect.Header.SizeOfRawData);
        FillChar((Section + ImportSect.Header.SizeOfRawData - $1000)^, $1000, 0);
        Strs := Section + Diff;
        Pointer(Descriptors) := Section;
      end;
    end;
  end;

  ImportSect.Data := Section;
  with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] do
  begin
    VirtualAddress := ImportSect.Header.VirtualAddress;
    Size := Thunks.Count * SizeOf(TImageImportDescriptor);
  end;

  Thunks.Free;

  FIATImage := IAT;
  FIATImageSize := IATSize;

  Result := PE;
end;

procedure TDumper.GatherModuleExportsFromRemoteProcess(M: PRemoteModule);
var
  Head: PByte;
  ExpDataDir: TImageDataDirectory;
  Exp: PImageExportDirectory;
  Off: PByte;
  a, n: PCardinal;
  o: PWord;
  i: Integer;
  Named: array of Boolean;
  FuncIndex: Cardinal;
  Fwd: PAnsiChar;
begin
  GetMem(Head, $1000);
  try
    RPM(NativeUInt(M.Base), Head, $1000);
    ExpDataDir := PImageNtHeaders(Head + PImageDosHeader(Head)._lfanew).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExpDataDir.VirtualAddress = 0) or (ExpDataDir.Size < SizeOf(TImageExportDirectory)) then
      Exit;

    GetMem(Exp, ExpDataDir.Size);
    RPM(NativeUInt(M.Base + ExpDataDir.VirtualAddress), Exp, ExpDataDir.Size);
    Off := PByte(Exp) - ExpDataDir.VirtualAddress;
  finally
    FreeMem(Head);
  end;

  Pointer(a) := Off + Exp.AddressOfFunctions;
  Pointer(n) := Off + Exp.AddressOfNames;
  Pointer(o) := Off + Exp.AddressOfNameOrdinals;

  SetLength(Named, Exp.NumberOfFunctions);
  FillChar(Named[0], Length(Named) * SizeOf(Boolean), 0);

  for i := 0 to Exp.NumberOfNames - 1 do
  begin
    FuncIndex := o[i];
    Named[FuncIndex] := True;
    M.ExportTbl.AddOrSetValue(M.Base + a[FuncIndex], string(AnsiString(PAnsiChar(Off + n[i]))));
  end;
  for i := 0 to Exp.NumberOfFunctions - 1 do
  begin
    // Add ordinals
    if not Named[i] then
    begin
      FuncIndex := Exp.Base + UInt32(i);
      M.ExportTbl.AddOrSetValue(M.Base + a[i], '#' + IntToStr(FuncIndex));
    end;

    // Check if entry is forward
    if (a[i] > ExpDataDir.VirtualAddress) and (a[i] < ExpDataDir.VirtualAddress + ExpDataDir.Size) then
    begin
      Fwd := PAnsiChar(Off + a[i]); // e.g. 'NTDLL.RtlAllocateHeap'
      if Pos(AnsiString('.#'), Fwd) = 0 then
      begin
        M.Forwards.Add(TForward.Create(string(AnsiString(Fwd)), M.Base + a[i]));
      end;
    end;
  end;

  FreeMem(Exp);
end;

{$IFDEF CPUX86}
procedure TDumper.CollectSpecialUser32Forwards(User32RM: PRemoteModule);
var
  ModScan: PByte;
  ExpDataDir: TImageDataDirectory;
  ExpDir: PImageExportDirectory;
  i: Integer;
  a: PCardinal;
  Fwd: PAnsiChar;
begin
  // Scan specially loaded user32 copy, because forwards are patched out in normally loaded user32 images.
  ModScan := Pointer(FHUsr);
  ExpDataDir := PImageNTHeaders(ModScan + PImageDosHeader(ModScan)._lfanew).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  ExpDir := Pointer(ModScan + ExpDataDir.VirtualAddress);

  a := PCardinal(ModScan + ExpDir.AddressOfFunctions);
  for i := 0 to ExpDir.NumberOfFunctions - 1 do
  begin
    Fwd := PAnsiChar(ModScan + a^);
    if (PByte(Fwd) > ModScan + ExpDataDir.VirtualAddress) and (PByte(Fwd) < ModScan + ExpDataDir.VirtualAddress + ExpDataDir.Size) and (Pos(AnsiString('.#'), Fwd) = 0) then
    begin
      User32RM.Forwards.Add(TForward.Create(string(AnsiString(Fwd)), nil));
    end;
    Inc(a);
  end;
end;
{$ENDIF}

procedure TDumper.ResolveForwards(M: PRemoteModule);
var
  Fwd: TForward;
  DotPos: Integer;
  ForwardModName, ForwardAPIName: string;
  ForwardMod: PRemoteModule;
  APISetResolved: HMODULE;
  Exprt: TPair<Pointer, string>;
  ProcAddr, FwdValue: Pointer;
begin
  for Fwd in M.Forwards do
  begin
    //Log(ltInfo, M.Name + ' --> ' + Fwd.Key);

    DotPos := Pos('.', Fwd.Key);
    ForwardModName := Copy(Fwd.Key, 1, DotPos - 1);
    if Pos('-ms-win-', ForwardModName) = 4 then // api-ms-win, ext-ms-win
    begin
      // Take a shortcut by resolving this locally.
      APISetResolved := GetModuleHandle(PChar(ForwardModName));
      if APISetResolved <> 0 then
        ForwardMod := GetRemoteModule(APISetResolved)
      else
        ForwardMod := nil;
    end
    else
      ForwardMod := GetRemoteModule(ForwardModName + '.dll');

    if ForwardMod <> nil then
    begin
      ForwardAPIName := Copy(Fwd.Key, DotPos + 1, 50);
      ProcAddr := nil;
      for Exprt in ForwardMod.ExportTbl do
        if Exprt.Value = ForwardAPIName then
        begin
          ProcAddr := Exprt.Key;
          Break;
        end;

      if ProcAddr <> nil then
      begin
        if not FForwards.ContainsKey(ProcAddr) then
          FForwards.Add(ProcAddr, TList<TForwardOrigin>.Create);
        FwdValue := Fwd.Value;
        {$IFDEF CPUX86}
        if M.Name = 'user32.dll' then
          FwdValue := ProcAddr; // user32 ExportTbl has the patched (resolved) values
        {$ENDIF}
        FForwards[ProcAddr].Add(TForwardOrigin.Create(M, FwdValue));
      end;
      //Log(ltInfo, Format('%s @ %p', [ForwardAPIName, ProcAddr]));
    end
    //else
    //  Log(ltFatal, Format('Forward target not loaded: %s', [ForwardModName]));
  end;
end;

function TDumper.GetRemoteModule(Base: HMODULE): PRemoteModule;
begin
  for Result in FAllModules do
    if HMODULE(Result.Base) = Base then
      Exit;
  Result := nil;
end;

function TDumper.GetRemoteModule(const Name: string): PRemoteModule;
begin
  for Result in FAllModules do
    if Result.Name = LowerCase(Name) then
      Exit;
  Result := nil;
end;

function TDumper.IsAPIAddress(Address: NativeUInt): Boolean;
var
  RM: PRemoteModule;
begin
  if FAllModules = nil then
    TakeModuleSnapshot;

  for RM in FAllModules do
    if (Address >= NativeUInt(RM.Base)) and (Address < NativeUInt(RM.EndOff)) then
      Exit(RM.ExportTbl.ContainsKey(Pointer(Address)));

  Result := False;
end;

procedure TDumper.TakeModuleSnapshot;
var
  hSnap: THandle;
  ME: TModuleEntry32;
  RM: PRemoteModule;
begin
  FAllModules := TList<PRemoteModule>.Create;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, FProcess.dwProcessId);
  ME.dwSize := SizeOf(TModuleEntry32);
  if not Module32First(hSnap, ME) then
    raise Exception.Create('Module32First');
  repeat
    if ME.hModule <> FImageBase then
    begin
      //Log(ltInfo, IntToHex(ME.hModule, 8) + ' : ' + IntToHex(ME.modBaseSize, 4) + ' : ' + string(ME.szModule));
      New(RM);
      RM.Base := ME.modBaseAddr;
      RM.EndOff := ME.modBaseAddr + ME.modBaseSize;
      RM.Name := LowerCase(ME.szModule);
      RM.ExportTbl := TExportTable.Create;
      RM.Forwards := TList<TForward>.Create;
      GatherModuleExportsFromRemoteProcess(RM);
      {$IFDEF CPUX86}
      if (RM.Name = 'user32.dll') and (FHUsr <> 0) then
        CollectSpecialUser32Forwards(RM);
      {$ENDIF}
      FAllModules.Add(RM);
    end;
  until not Module32Next(hSnap, ME);
  CloseHandle(hSnap);

  for RM in FAllModules do
    ResolveForwards(RM);
end;

function TDumper.RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
begin
  Result := ReadProcessMemory(FProcess.hProcess, Pointer(Address), Buf, BufSize, BufSize);
  if not Result then
    Log(ltFatal, 'RPM failed');
end;

procedure TDumper.MakeMemoryReadable(Base, Size: NativeUInt);
var
  mbi: MEMORY_BASIC_INFORMATION;
  Addr: NativeUInt;
  EndAddr: NativeUInt;
  BytesReturned: SIZE_T;
  OldProtect: DWORD;
begin
  Addr := Base;
  EndAddr := Addr + Size;

  while Addr < EndAddr do
  begin
    BytesReturned := VirtualQueryEx(FProcess.hProcess, Pointer(Addr), mbi, SizeOf(mbi));

    if BytesReturned = 0 then
      Break;

    if (mbi.State = MEM_COMMIT) and (mbi.Protect = PAGE_NOACCESS) then
      VirtualProtectEx(FProcess.hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_READONLY, @OldProtect);

    Addr := NativeUInt(mbi.BaseAddress) + mbi.RegionSize;
  end;
end;

class procedure TDumper.SwitchSxSManifestType(S: TStream; PE: TPEHeader; SwitchFrom, SwitchTo: Integer);
var
  Rsrc: PPESection;
  RsrcSize, Offset, i, ManifestSubDir, IDOffset: DWORD;
  RsrcData: PByte;
  NumNamed, NumID: Word;
begin
  // This function changes the manifest type between EXE/DLL so side-by-side functionality (like pinned MSVC versions) works properly.
  if PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = 0 then
    Exit;

  Rsrc := PE.GetSectionByVA(PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
  RsrcSize := PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
  S.Seek(Rsrc.Header.PointerToRawData, soBeginning);
  GetMem(RsrcData, RsrcSize);
  try
    S.Read(RsrcData^, RsrcSize);

    NumNamed := PWord(RsrcData + $C)^;
    NumID := PWord(RsrcData + $E)^;
    if NumID = 0 then
      Exit;

    Offset := $10 + NumNamed * 8;
    ManifestSubDir := 0;
    for i := 0 to NumID - 1 do
      if PInteger(RsrcData + Offset + i * 8)^ = 24 then // MANIFEST
      begin
        ManifestSubDir := PCardinal(RsrcData + Offset + i * 8 + 4)^;
        Break;
      end;

    if (ManifestSubDir = 0) or (ManifestSubDir shr 31 <> 1) then
      Exit;

    ManifestSubDir := ManifestSubDir and $7FFFFFFF;
    if (PWord(RsrcData + ManifestSubDir + $C)^ <> 0) or (PWord(RsrcData + ManifestSubDir + $E)^ <> 1) then
    begin
      Log(ltInfo, 'Encountered weird manifest resource dir');
      Exit;
    end;

    IDOffset := ManifestSubDir + $10;
    if PInteger(RsrcData + IDOffset)^ <> SwitchFrom then
      Exit;

    S.Seek(Rsrc.Header.PointerToRawData + IDOffset, soBeginning);
    S.Write(SwitchTo, 4);
  finally
    FreeMem(RsrcData);
  end;
end;

function TDumper.GetOriginalImports(const FileName: string): TList<TOriginalImport>;
var
  FS: TFileStream;
  HeaderBuf, SectBuf: PByte;
  FilePE: TPEHeader;
  ImportDir: TImageDataDirectory;
  Sect: PPESection;
  Descriptor: PImageImportDescriptor;
  ThunkAddr: PNativeUInt;
  Thunk: NativeUInt;
  DllName: AnsiString;
  Import: TOriginalImport;
begin
  Result := nil;

  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  GetMem(HeaderBuf, $1000);
  try
    FS.ReadBuffer(HeaderBuf^, $1000);
    FilePE := TPEHeader.Create(HeaderBuf);
    try
      ImportDir := FilePE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
      if (ImportDir.VirtualAddress = 0) or (ImportDir.Size = 0) then
        Exit;

      Sect := FilePE.GetSectionByVA(ImportDir.VirtualAddress);
      if Sect = nil then
        Exit;

      GetMem(SectBuf, Sect.Header.SizeOfRawData);
      try
        FS.Position := Sect.Header.PointerToRawData;
        FS.ReadBuffer(SectBuf^, Sect.Header.SizeOfRawData);

        Result := TList<TOriginalImport>.Create;
        Descriptor := PImageImportDescriptor(SectBuf + (ImportDir.VirtualAddress - Sect.Header.VirtualAddress));

        while Descriptor.Name <> 0 do
        begin
          DllName := AnsiString(PAnsiChar(SectBuf + (Descriptor.Name - Sect.Header.VirtualAddress)));

          ThunkAddr := PNativeUInt(SectBuf + (Descriptor.FirstThunk - Sect.Header.VirtualAddress));
          while ThunkAddr^ <> 0 do
          begin
            Import.DLLName := LowerCase(string(DllName));
            Thunk := ThunkAddr^;
            if (Thunk and IMAGE_ORDINAL_FLAG) <> 0 then
              Import.FuncName := '#' + IntToStr(Thunk and $FFFF)
            else
              Import.FuncName := string(AnsiString(PAnsiChar(SectBuf + (Thunk - Sect.Header.VirtualAddress) + 2)));
            Result.Add(Import);
            Inc(ThunkAddr);
          end;

          Inc(Descriptor);
        end;
      finally
        FreeMem(SectBuf);
      end;
    finally
      FilePE.Free;
    end;
  finally
    FreeMem(HeaderBuf);
    FS.Free;
  end;
end;

function TDumper.HasOriginalImport(const DLL, Func: string): Boolean;
var
  OI: TOriginalImport;
begin
  for OI in FOriginalImports do
    if (OI.DLLName = DLL) and (OI.FuncName = Func) then
      Exit(True);
  Result := False;
end;

{ TDumperDotnet }

constructor TDumperDotnet.Create(const AProcess: TProcessInformation; AImageBase: UIntPtr);
begin
  FProcess := AProcess;
  FImageBase := AImageBase;
end;

procedure TDumperDotnet.DumpToFile(const FileName: string);
var
  FS: TFileStream;
  Header: array[0..$FFF] of Byte;
  PE: TPEHeader;
  Buf, Ptr: PByte;
  Size, PhysicalSize, ImageSize, Done: DWORD;
  NumRead: UIntPtr;
  Mbi: TMemoryBasicInformation;
begin
  // Dumping Themida .NET binaries appears to be quite simple because
  // no special imports processing is required.
  NumRead := 0;
  if not ReadProcessMemory(FProcess.hProcess, Pointer(FImageBase), @Header, $1000, NumRead) then
    raise Exception.Create('DumpToFile header RPM failed');

  PE := TPEHeader.Create(@Header);
  with PE.Sections[PE.NTHeaders.FileHeader.NumberOfSections - 1] do
    Size := Header.VirtualAddress + Header.Misc.VirtualSize;

  FS := TFileStream.Create(FileName, fmCreate);
  GetMem(Buf, Size);
  try
    PhysicalSize := Size;
    PE.FileAlign(PhysicalSize);
    ImageSize := PhysicalSize;
    PE.SectionAlign(ImageSize);
    PE.NTHeaders.OptionalHeader.SizeOfImage := ImageSize;
    PE.Sections[0].Rename('.text');

    Log(ltInfo, Format('Output has %d sections, determined size to be 0x%X', [PE.NTHeaders.FileHeader.NumberOfSections, Size]));

    Ptr := PByte(FImageBase);
    Done := 0;
    Mbi.RegionSize := $1000;
    while Done < Size do
    begin
      if VirtualQueryEx(FProcess.hProcess, Ptr, Mbi, SizeOf(Mbi)) = 0 then
        raise Exception.CreateFmt('VirtualQueryEx failed at %p', [Ptr]);
      if Mbi.RegionSize = 0 then
        raise Exception.CreateFmt('VirtualQueryEx returned a zero region at %p', [Ptr]); // Idk if/why it would but we wouldn't make any progress then

      if Mbi.State = MEM_COMMIT then
      begin
        NumRead := 0;
        if not ReadProcessMemory(FProcess.hProcess, Ptr, Buf + Done, Min(Size - Done, Mbi.RegionSize), NumRead) then
          raise Exception.Create('DumpToFile RPM failed');
      end
      else if Mbi.State = MEM_RESERVE then
      begin
        // We could mess with the section addresses and leave this chunk out of the physical file, but eh...
        FillChar((Buf + Done)^, Min(Size - Done, Mbi.RegionSize), 0);
      end
      else
        raise Exception.CreateFmt('Got unexpected region state %X at %p', [Mbi.State, Ptr]);

      Inc(Done, Mbi.RegionSize);
      Inc(Ptr, Mbi.RegionSize);
    end;

    FS.Write(Buf^, Size);
    if Size < PhysicalSize then
    begin
      // Pad to file alignment
      ReallocMem(Buf, PhysicalSize - Size);
      FillChar(Buf^, PhysicalSize - Size, 0);
      FS.Write(Buf^, PhysicalSize - Size);
    end;

    PE.SaveToStream(FS);
  finally
    FreeMem(Buf);
    PE.Free;
    FS.Free;
  end;
end;

{ TImportThunk }

constructor TImportThunk.Create(RM: PRemoteModule);
begin
  Module := RM;
  Name := RM.Name;
  Addresses := TList<PPointer>.Create;
end;

destructor TImportThunk.Destroy;
begin
  Addresses.Free;

  inherited;
end;

{ TForward }

constructor TForward.Create(const AKey: string; AValue: Pointer);
begin
  Key := AKey;
  Value := AValue;
end;

{ TForwardOrigin }

constructor TForwardOrigin.Create(ASourceModule: PRemoteModule; ASourceAddress: Pointer);
begin
  SourceModule := ASourceModule;
  SourceAddress := ASourceAddress;
end;

end.
