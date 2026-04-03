# Use the official Node.js 20 Alpine image as a base
FROM node:20-alpine

# Set the working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install production dependencies
RUN npm ci --omit=dev

# Copy the rest of the application code
COPY server.js ./

# Expose the port the app runs on
EXPOSE 3005

# Start the application
CMD ["node", "server.js"]
