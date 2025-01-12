FROM mcr.microsoft.com/dotnet/sdk:9.0

# Set the working directory
WORKDIR /sib22idaustria-backend

# Copy all files into the working directory
COPY . /sib22idaustria-backend

# Remove all possible .env files
RUN rm -f *.env

# Build the project in release mode
RUN dotnet build --configuration Release

# Expose the port
EXPOSE 8080

# Run the project on container start (JSON array form recommended)
CMD ["dotnet", "bin/Release/net9.0/sib22idaustria-backend.dll"]
