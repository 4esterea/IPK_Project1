ASM_NAME = "ipk-l4-scan"

BUILD: CLEAN *.cs *.csproj
	dotnet publish -c Release -o .

CLEAN:
	dotnet restore
	dotnet clean
	rm -rf bin obj $(ASM_NAME) $(ASM_NAME).pdb

ZIP: CLEAN
	zip -r $(shell basename $(shell pwd)).zip .