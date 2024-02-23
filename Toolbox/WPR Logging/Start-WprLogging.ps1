#Requires -RunAsAdministrator

$wprp = @'
<?xml version="1.0" encoding="utf-8"?>
<WindowsPerformanceRecorder Version="1.0" Author="Microsoft Corporation" Copyright="Microsoft Corporation" Company="Microsoft Corporation">
	<Profiles>
		<EventCollector Id="EventCollector_MDMTraceLoggingProvider" Name="MDMTraceLoggingProviderCollector">
			<BufferSize Value="8192"/>
			<Buffers Value="32"/>
		</EventCollector>
		<Profile Id="MDMTraceLoggingProvider.Verbose.File" Name="MDMTraceLoggingProvider" Description="AllMDMTraceLoggingProvider" LoggingMode="File" DetailLevel="Verbose">
			<Collectors>
				<EventCollectorId Value="EventCollector_MDMTraceLoggingProvider">
					<EventProviders>
						<EventProvider Id="EventProvider_AADCorePlugin" Name="4DE9BC9C-B27A-43C9-8994-0915F1A5E24F"/>
						<EventProvider Id="EventProvider_ADMXIngestion" Name="64E05266-27B6-4F6B-AB9E-AB7CC9497089"/>
						<EventProvider Id="EventProvider_CertificateStore" Name="536D7120-A8A4-4A5F-B1F8-1735DF9B78D0"/>
						<EventProvider Id="EventProvider_ConfigManager2" Name="0BA3FB88-9AF5-4D80-B3B3-A94AC136B6C5"/>
						<EventProvider Id="EventProvider_ConfigManager2HookGuid" Name="76FA08A3-6807-48DB-855D-2C12702630EF"/>
						<EventProvider Id="EventProvider_Container" Name="E1235DFE-7622-4B39-810A-4B78D3E48E36"/>
						<EventProvider Id="EventProvider_DMAccXperfGuid" Name="E1A8D70D-11F0-420E-A170-29C6B686342D"/>
						<EventProvider Id="EventProvider_DMClient" Name="36a529a2-7cba-4370-8c3d-d113f552b138"/>
						<EventProvider Id="EventProvider_DMCmnUtils" Name="0A8E17FD-ED19-4C54-A1E7-5A2829BF507F"/>
						<EventProvider Id="EventProvider_DMSvc" Name="8CC7D9C9-09AF-45CA-86CE-4CECF680F2B7"/>
						<EventProvider Id="EventProvider_DeclaredConfiguration" Name="5AFBA129-D6B7-4A6F-8FC0-B92EC134C86C"/>
						<EventProvider Id="EventProvider_DevInfoCSP" Name="FE5A93CC-0B38-424A-83B0-3C3FE2ACB8C9"/>
						<EventProvider Id="EventProvider_DeviceManagementSettings" Name="a8fd7a5b-4323-4172-b85b-f5b78c3c0f9c"/>
						<EventProvider Id="EventProvider_Dynamo" Name="C15421A9-1A99-474E-9E1B-F16AC98E173D"/>
						<EventProvider Id="EventProvider_EDPCleanupTraceLoggingProvider" Name="e42598b4-b399-41cd-a67c-a6b1b6007e07"/>
						<EventProvider Id="EventProvider_EdpConfigurationTraceProvider" Name="6BE7190D-DBA0-5E9C-8B69-C5A9AED40FB9"/>
						<EventProvider Id="EventProvider_EnrollmentEtwProvider" Name="9FBF7B95-0697-4935-ADA2-887BE9DF12BC"/>
						<EventProvider Id="EventProvider_EnterpriseDesktopAppManagement" Name="16EAA7BB-5B6E-4615-BF44-B8195B5BF873"/>
						<EventProvider Id="EventProvider_MDMDiagnostics" Name="bf5f1ee5-5dc0-4836-9f23-889294c42a54"/>
						<EventProvider Id="EventProvider_MdmEvaluatorTraceProvider" Name="8F453BA5-F19E-531D-071B-72BA1C501406"/>
						<EventProvider Id="EventProvider_MdmPush" Name="6e7d2591-6d94-5b84-02a1-c74c54de1719"/>
						<EventProvider Id="EventProvider_Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider" Name="3DA494E4-0FE2-415C-B895-FB5265C5C83B"/>
						<EventProvider Id="EventProvider_Microsoft-WindowsPhone-OmaDm-Client-Provider" Name="3B9602FF-E09B-4C6C-BC19-1A3DFA8F2250"/>
						<EventProvider Id="EventProvider_Microsoft.Windows.EnterpriseModernAppManagement" Name="0e71a49b-ca69-5999-a395-626493eb0cbd"/>
						<EventProvider Id="EventProvider_NodeCache" Name="24a7f60e-e0cb-5bdc-99a5-0ba8e8c018bd"/>
						<EventProvider Id="EventProvider_OMADMAPI" Name="7D85C2D0-6490-4BB4-BAC1-247D0BD06F10"/>
						<EventProvider Id="EventProvider_OmaDMAgent" Name="ACCA0101-AE51-4D60-A32A-552A6B1DEABE"/>
						<EventProvider Id="EventProvider_OmaDMApi" Name="86625C04-72E1-4D36-9C86-CA142FD0A946"/>
						<EventProvider Id="EventProvider_OmacpClient" Name="FF036693-0480-41DD-AC12-ED3C6A936A5F"/>
						<EventProvider Id="EventProvider_OmadmClient" Name="0EC685CD-64E4-4375-92AD-4086B6AF5F1D"/>
						<EventProvider Id="EventProvider_OmadmPrc" Name="797C5746-634F-4C59-8AE9-93F900670DCC"/>
						<EventProvider Id="EventProvider_PolicyManagerXperfGuid" Name="FFDB0CFD-833C-4F16-AD3F-EC4BE3CC1AF5"/>
						<EventProvider Id="EventProvider_PushRouterAuth" Name="455FEFE7-5B3D-485A-BCBB-D0F09A47D1AE"/>
						<EventProvider Id="EventProvider_PushRouterCore" Name="0E316AA7-3B31-4D58-9B8B-10B3B2C0F2ED"/>
						<EventProvider Id="EventProvider_PushRouterProxy" Name="83AFAF72-DF00-4584-8F4C-ADED166F72B1"/>
						<EventProvider Id="EventProvider_RemoteFind" Name="11838EF3-69E8-4FF0-8116-B2FFDDF289C9"/>
						<EventProvider Id="EventProvider_ResourceMgr" Name="6B865228-DEFA-455A-9E25-27D71E8FE5FA"/>
						<EventProvider Id="EventProvider_SCEP" Name="D5A5B540-C580-4DEE-8BB4-185E34AA00C5"/>
						<EventProvider Id="EventProvider_SampledEnrollmentProvider" Name="e74efd1a-b62d-4b83-ab00-66f4a166a2d3"/>
						<EventProvider Id="EventProvider_SecurityPolicyCSP" Name="F058515F-DBB8-4C0D-9E21-A6BC2C422EAB"/>
						<EventProvider Id="EventProvider_UnenrollHook" Name="6222F3F1-237E-4B0F-8D12-C20072D42197"/>
						<EventProvider Id="EventProvider_UnsampledEnrollmentProvider" Name="F9E3B648-9AF1-4DC3-9A8E-BF42C0FBCE9A"/>
						<EventProvider Id="EventProvider_W7NodeProcessor" Name="33466AA0-09A2-4C47-9B7B-1B8A4DC3A9C9"/>
						<EventProvider Id="EventProvider_WMIBridge" Name="A76DBA2C-9683-4BA7-8FE4-C82601E117BB"/>
						<EventProvider Id="EventProvider_WMICSP" Name="C37BB754-DC5C-45AD-9D00-A42CFCF137A8"/>
						<EventProvider Id="EventProvider_WMITraceLoggingProvider" Name="A76DBA2C-9683-4BA7-8FE4-C82601E117BB"/>
						<EventProvider Id="EventProvider_WapXperfGuid" Name="18F2AB69-92B9-47E4-B9DB-B4AC2E4C7115"/>
						<EventProvider Id="EventProvider_WindowsAttestation" Name="0a611b27-ba1a-4acf-9c91-ea1611e24c38"/>
						<EventProvider Id="EventProvider_Microsoft-Windows-TPM-WMI" Name="7d5387b0-cbe0-11da-a94d-0800200c9a66"/>
						<EventProvider Id="EventProvider_Microsoft.Windows.Security.TokenBroker" Name="*Microsoft.Windows.Security.TokenBroker">
						<EventProvider Id="EventProvider-Microsoft.Tpm.DebugTracing" Name="3a8d6942-b034-48e2-b314-f69c2b4655a3"/>
						<EventProvider Id="EventProvider-Microsoft.Tpm.HealthAttestationCSP" Name="a935c211-645a-5f5a-4527-778da45bbba5"/>
						<EventProvider Id="EventProvider-Microsoft.Tpm.ProvisioningTask" Name="470baa67-2d7f-4c9c-8bf4-b1b3226f7b17"/>
							<Keywords>
								<Keyword Value="0x0000600000000000"/>
							</Keywords>
						</EventProvider>
					</EventProviders>
				</EventCollectorId>
			</Collectors>
		</Profile>
		<Profile Id="MDMTraceLoggingProvider.Verbose.Memory" Name="MDMTraceLoggingProvider" Description="AllMDMTraceLoggingProvider" Base="MDMTraceLoggingProvider.Verbose.File" LoggingMode="Memory" DetailLevel="Verbose"/>
		<Profile Id="MDMTraceLoggingProvider.Light.Memory" Name="MDMTraceLoggingProvider" Description="AllMDMTraceLoggingProvider" Base="MDMTraceLoggingProvider.Verbose.File" LoggingMode="Memory" DetailLevel="Light"/>
		<Profile Id="MDMTraceLoggingProvider.Light.File" Name="MDMTraceLoggingProvider" Description="AllMDMTraceLoggingProvider" Base="MDMTraceLoggingProvider.Verbose.File" LoggingMode="File" DetailLevel="Light"/>
	</Profiles>
</WindowsPerformanceRecorder>
'@

if (!(Test-Path -Path 'C:\Temp\Toolbox\TraceLogs')) {
    New-Item -Path 'C:\Temp\Toolbox\TraceLogs' -ItemType Directory -Force -ErrorAction Stop
}

$wprp | Out-File -FilePath 'C:\Temp\Toolbox\TraceLogs\TraceLog.wprp' -Force -Encoding utf8

wpr.exe -start C:\Temp\Toolbox\TraceLogs\TraceLog.wprp
wpr.exe -status

