###############################################################################
# Metadata
'''
LC_PATROL_MTD_START
{
    "description" : "Collection of all core LimaCharlie.io detections.",
    "stateless" : "VirusTotalKnownBad, MalwareDomainsIoc, WinSuspExecLoc, WinSuspExecName, MacSuspExecLoc, ShadowVolumeTampering, AclTampering",
    "stateful" : "WinScriptedPayload, WinDocumentExploit, MacDocumentExploit",
    "hunter" : "VirusTotalHunter, Stage0Hunter",
    "author" : "maximelb@google.com",
    "version" : "1.0"
}
LC_PATROL_MTD_END
'''
###############################################################################


#######################################
# stateless/VirusTotalKnownBad
# This actor checks all hashes against
# VirusTotal and reports hashes that
# have more than a threshold of AV
# reports, while caching results.
# Parameters:
# min_av: minimum number of AV reporting
#    a result on the hash before it is
#    reported as a detection.
#######################################
Patrol( 'VirusTotalKnownBad',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 2000,
        actorArgs = ( 'stateless/VirusTotalKnownBad',
                      [ 'analytics/stateless/common/notification.CODE_IDENTITY/virustotalknownbad/1.0',
                        'analytics/stateless/common/notification.OS_SERVICES_REP/virustotalknownbad/1.0',
                        'analytics/stateless/common/notification.OS_DRIVERS_REP/virustotalknownbad/1.0',
                        'analytics/stateless/common/notification.OS_AUTORUNS_REP/virustotalknownbad/1.0' ] ),
        actorKwArgs = {
            'parameters' : { 'min_av' : 7 },
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 50,
            'strategy' : 'repulsion' } )

#######################################
# stateless/MalwareDomainsIoc
# This actor checks all hashes against
# VirusTotal and reports hashes that
# have more than a threshold of AV
# reports, while caching results.
# Parameters:
# min_av: minimum number of AV reporting
#    a result on the hash before it is
#    reported as a detection.
#######################################
Patrol( 'MalwareDomainsIoc',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 2000,
        actorArgs = ( 'stateless/MalwareDomainsIoc',
                      [ 'analytics/stateless/common/notification.DNS_REQUEST/malwaredomains/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 50 } )

#######################################
# stateless/WinSuspExecLoc
# This actor looks for execution from
# various known suspicious locations.
#######################################
Patrol( 'WinSuspExecLoc',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/WinSuspExecLoc',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/suspexecloc/1.0',
                        'analytics/stateless/windows/notification.CODE_IDENTITY/suspexecloc/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateless/WinSuspExecName
# This actor looks for execution from
# executables with suspicious names that
# try to hide the fact the files are
# executables.
#######################################
Patrol( 'WinSuspExecName',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/WinSuspExecName',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/suspexecname/1.0',
                        'analytics/stateless/windows/notification.CODE_IDENTITY/suspexecname/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateless/MacSuspExecLoc
# This actor looks for execution from
# various known suspicious locations.
#######################################
Patrol( 'MacSuspExecLoc',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/MacSuspExecLoc',
                      [ 'analytics/stateless/osx/notification.NEW_PROCESS/suspexecloc/1.0',
                        'analytics/stateless/osx/notification.CODE_IDENTITY/suspexecloc/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateless/ShaowVolumeTampering
# This actor looks for execution from
# executables with suspicious names that
# try to hide the fact the files are
# executables.
#######################################
Patrol( 'ShadowVolumeTampering',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/ShadowVolumeTampering',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/shadowvolumetampering/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateless/AclTampering
# This actor looks for execution from
# executables with suspicious names that
# try to hide the fact the files are
# executables.
#######################################
Patrol( 'AclTampering',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 1000,
        actorArgs = ( 'stateless/AclTampering',
                      [ 'analytics/stateless/windows/notification.NEW_PROCESS/acltampering/1.0' ] ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateful/WinScriptedPayload
# This actor looks for a payload executing
# under a scripting engine.
#######################################
Patrol( 'WinScriptedPayload',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/WinScriptedPayload',
                      'analytics/stateful/modules/windows/scriptedpayload/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateful/WinDocumentExploit
# This actor looks for various stateful
# patterns indicating documents being
# exploited.
#######################################
Patrol( 'WinDocumentExploit',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/WinDocumentExploit',
                      'analytics/stateful/modules/windows/documentexploit/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# stateful/MacDocumentExploit
# This actor looks for various stateful
# patterns indicating documents being
# exploited.
#######################################
Patrol( 'MacDocumentExploit',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 500,
        actorArgs = ( 'stateful/MacDocumentExploit',
                      'analytics/stateful/modules/osx/documentexploit/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5,
            'strategy' : 'repulsion' } )

#######################################
# hunter/Stage0Hunter
# This hunter investigates potential
# stage 0.
#######################################
Patrol( 'Stage0Hunter',
        initialInstances = 1,
        maxInstances = None,
        relaunchOnFailure = True,
        onFailureCall = None,
        scalingFactor = 10000,
        actorArgs = ( 'hunter/Stage0Hunter',
                      'analytics/hunter/stage0hunter/1.0' ),
        actorKwArgs = {
            'parameters' : {},
            'secretIdent' : 'hunter/8e0f55c0-6593-4747-9d02-a4937fa79517',
            'trustedIdents' : [ 'analysis/01e9a19d-78e1-4c37-9a6e-37cb592e3897' ],
            'n_concurrent' : 5 } )
