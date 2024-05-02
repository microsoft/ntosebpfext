rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT

sc stop ntosebpfext
msbuild /m /t:Rebuild ntosebpfext.sln /p:Configuration=Debug /p:Platform=x64
sc start ntosebpfext