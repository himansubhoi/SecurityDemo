FROM microsoft/aspnetcore:2.0-nanoserver-1709 AS base
WORKDIR /app
EXPOSE 80

FROM microsoft/aspnetcore-build:2.0-nanoserver-1709 AS build
WORKDIR /src
COPY SecurityDemo/SecurityDemo.csproj SecurityDemo/
RUN dotnet restore SecurityDemo/SecurityDemo.csproj
COPY . .
WORKDIR /src/SecurityDemo
RUN dotnet build SecurityDemo.csproj -c Release -o /app

FROM build AS publish
RUN dotnet publish SecurityDemo.csproj -c Release -o /app

FROM base AS final
WORKDIR /app
COPY --from=publish /app .
ENTRYPOINT ["dotnet", "SecurityDemo.dll"]
