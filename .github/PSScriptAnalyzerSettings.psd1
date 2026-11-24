# PSScriptAnalyzer configuration for the CI lint gate.
#
# This is the PowerShell counterpart to the shellcheck job that already guards install-guard.sh.
# The Windows installer had no static analysis at all, which is how a WMI cmdlet removed in
# PowerShell 6 sat in it unnoticed -- the CI shell is pwsh 7, so nothing in the repository would
# have caught it before a user did.
#
# The gate runs with every default rule enabled except the exclusion below, so a new finding fails
# the build rather than accumulating.
@{
    Severity = @('Error', 'Warning', 'Information')

    ExcludeRules = @(
        # PSAvoidUsingWriteHost objects to Write-Host because its output cannot be captured or
        # redirected, which is the right call for a module or a library returning data to a caller.
        # install-guard.ps1 is neither: it is an interactive installer whose output is progress
        # commentary for a human watching a terminal, and the README documents piping it straight
        # into Invoke-Expression. Write-Output would put that commentary into the pipeline, where
        # it would be mistaken for the return value of the functions that emit it -- Get-ArchType
        # and Get-GuardVersion both return values by writing to the pipeline, so mixing progress
        # text into it would actively break them.
        #
        # Suppressed here rather than per-line: it applies to every Write-Host in the file for the
        # same reason, and twenty-odd inline suppressions would obscure the code they annotate.
        'PSAvoidUsingWriteHost'
    )
}
