# Dot-source before a Windows GNU build:
#   . .\ci\windows-build-env.ps1
#   cargo check -p reacher_backend --locked --offline
#
# Uses existing Rust/MinGW under target/dev-tools and Git for Windows' Perl.
# Missing pure-Perl modules are installed locally; system PATH is not changed.
& {
    $ErrorActionPreference = 'Stop'
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $toolRoot = Join-Path $projectRoot 'target\dev-tools'
    $cargoBin = Join-Path $toolRoot 'cargo\bin'
    $mingwBin = Join-Path $toolRoot 'mingw64\bin'
    $toolBin = Join-Path $toolRoot 'bin'
    $gitCommand = Get-Command git.exe -ErrorAction Stop
    $gitRoot = Split-Path -Parent (Split-Path -Parent $gitCommand.Source)
    $gitBin = Join-Path $gitRoot 'usr\bin'
    $perlPath = Join-Path $gitBin 'perl.exe'
    $cygpath = Join-Path $gitBin 'cygpath.exe'

    foreach ($required in @((Join-Path $cargoBin 'cargo.exe'), (Join-Path $mingwBin 'gcc.exe'), (Join-Path $mingwBin 'mingw32-make.exe'), $perlPath, $cygpath)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Required project build tool is missing: $required"
        }
    }

    $moduleRoot = Join-Path $toolRoot 'perl-modules'
    $packages = @(
        @{
            Name = 'Locale-Maketext-Simple-0.21'
            Group = 'Locale'
            Module = 'Locale\Maketext\Simple.pm'
            Hash = 'b009ff51f4fb108d19961a523e99b4373ccf958d37ca35bf1583215908dca9a9'
        },
        @{
            Name = 'ExtUtils-MakeMaker-7.76'
            Group = 'ExtUtils'
            Module = 'ExtUtils\MakeMaker.pm'
            Hash = '30bcfd75fec4d512e9081c792f7cb590009d9de2fe285ffa8eec1be35a5ae7ca'
        },
        @{
            Name = 'Pod-Usage-2.05'
            Group = 'Pod'
            Module = 'Pod\Usage.pm'
            Hash = '100c27908757c56ebfeca8b7bf15a9867e449df663ff013de3855d183dfbea30'
        },
        @{
            Name = 'Pod-Simple-3.47'
            Group = 'Pod'
            Module = 'Pod\Simple.pm'
            Hash = 'ab3e3845337b78ee14b50fdbc68197c71f5ea66ebdde0870dee4e642c305c514'
        },
        @{
            Name = 'Pod-Escapes-1.07'
            Group = 'Pod'
            Module = 'Pod\Escapes.pm'
            Hash = 'dbf7c827984951fb248907f940fd8f19f2696bc5545c0a15287e0fbe56a52308'
        },
        @{
            Name = 'podlators-v6.0.2'
            Group = 'Pod'
            Module = 'Pod\Text.pm'
            Hash = '2992125eab7d2b1c5a2b15a26ad7955f7d989eba6c831abdcaf2000e86a91337'
        }
    )
    foreach ($package in $packages) {
        $moduleLibrary = Join-Path $moduleRoot ($package.Name + '\lib')
        if (-not (Test-Path -LiteralPath (Join-Path $moduleLibrary $package.Module))) {
            New-Item -ItemType Directory -Force -Path $moduleRoot | Out-Null
            $archive = Join-Path $moduleRoot ($package.Name + '.tar.gz')
            $url = 'https://www.cpan.org/modules/by-module/' + $package.Group + '/' + $package.Name + '.tar.gz'
            Invoke-WebRequest -UseBasicParsing $url -OutFile $archive
            if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $package.Hash) {
                throw "Perl module archive checksum mismatch: $($package.Name)"
            }
            tar.exe -xf $archive -C $moduleRoot
            if ($LASTEXITCODE -ne 0) { throw "Perl module extraction failed: $($package.Name)" }
        }

        # Git's Perl uses MSYS paths and colon-separated library directories.
        $moduleUnixPath = & $cygpath -u $moduleLibrary
        if ($LASTEXITCODE -ne 0) { throw 'Cannot convert the Perl library path.' }
        if ($env:PERL5LIB) {
            if ($env:PERL5LIB.Split(':') -notcontains $moduleUnixPath) {
                $env:PERL5LIB = $moduleUnixPath + ':' + $env:PERL5LIB
            }
        } else {
            $env:PERL5LIB = $moduleUnixPath
        }
    }

    # Preserve MSYS Perl's colon-separated paths when its shell invokes native make.
    if ($env:MSYS2_ENV_CONV_EXCL) {
        if ($env:MSYS2_ENV_CONV_EXCL.Split(';') -notcontains 'PERL5LIB') {
            $env:MSYS2_ENV_CONV_EXCL += ';PERL5LIB'
        }
    } else {
        $env:MSYS2_ENV_CONV_EXCL = 'PERL5LIB'
    }

    # openssl-src invokes "make", while WinLibs names its executable mingw32-make.
    New-Item -ItemType Directory -Force -Path $toolBin | Out-Null
    $makeAlias = Join-Path $toolBin 'make.exe'
    if (-not (Test-Path -LiteralPath $makeAlias)) {
        Copy-Item -LiteralPath (Join-Path $mingwBin 'mingw32-make.exe') -Destination $makeAlias
    }

    $env:CARGO_HOME = Join-Path $toolRoot 'cargo'
    $env:RUSTUP_HOME = Join-Path $toolRoot 'rustup'
    $env:PATH = $cargoBin + ';' + $toolBin + ';' + $mingwBin + ';' + $gitBin + ';' + $env:PATH
    $env:OPENSSL_SRC_PERL = $perlPath
    $env:SQLX_OFFLINE = 'true'
    # Existing aws-lc-sys uses CMake policies older than bundled CMake 4 supports.
    $env:CMAKE_POLICY_VERSION_MINIMUM = '3.5'

    & $perlPath -MLocale::Maketext::Simple -MExtUtils::MakeMaker -MIPC::Cmd -MPod::Usage -e 'die qq(gcc unavailable\n) unless IPC::Cmd::can_run(q(gcc)); print qq(OpenSSL Perl dependencies and compiler discovery verified\n)'
    if ($LASTEXITCODE -ne 0) { throw 'Perl build dependency verification failed.' }
    Write-Host 'Project-local Windows build environment is ready for this PowerShell session.'
}
