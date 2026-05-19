Write-Host "Please enter your publish key:"
$key = Read-Host
foreach($file in Get-ChildItem *.nupkg){
dotnet nuget push $file.name -k $key -s https://api.nuget.org/v3/index.json
}