How do I install Winget-Create?
You can either download the latest release of Winget-Create from its GitHub repository or use Winget to install it for you by running the following command:
winget install wingetcreate


Creating your manifest with Winget-Create
Now that you have Winget-Create installed onto your machine, you are ready to generate your first manifest by running the New command. To do so, simply run the following command in your terminal:
wingetcreate new <Installer URL(s)>

There are many other commands available in Winget-Create to help you update existing manifests or submit new manifests. Feel free to try it out!


Validation
If you decide to create or edit your manifest by manually editing the YAML, it is important to make sure that you are validating your manifest. You can do this by running the validate command from Winget which will tell you if your manifest is valid, or which parts need to be fixed:
winget validate --manifest <Path to manifest>