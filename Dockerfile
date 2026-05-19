FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY src/RinhaFraudDetection.csproj ./src/
COPY tools/Preprocessor/Preprocessor.csproj ./tools/Preprocessor/
RUN dotnet restore src/RinhaFraudDetection.csproj && dotnet restore tools/Preprocessor/Preprocessor.csproj

COPY src ./src
COPY tools/Preprocessor ./tools/Preprocessor

RUN dotnet run --project tools/Preprocessor -c Release -- src/Data/references.json.gz src/Data/references.bin
RUN dotnet publish src/RinhaFraudDetection.csproj -c Release -o /app

COPY src/Data/references.bin /app/Data/references.bin

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime
WORKDIR /app
COPY --from=build /app .
RUN apk add --no-cache libstdc++
ENV DOTNET_EnableWriteXorExecute=0
EXPOSE 8080
ENTRYPOINT ["dotnet", "RinhaFraudDetection.dll"]
