ASM_NAME = "ipk-l4-scan"

CLEAN:
	dotnet restore
	dotnet clean
	rm -rf bin obj $(ASM_NAME) $(ASM_NAME).pdb

BUILD: CLEAN *.cs *.csproj
	dotnet publish -c Release -o .

ZIP: CLEAN
	zip -r $(shell basename $(shell pwd)).zip .