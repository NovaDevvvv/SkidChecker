module.exports = {
  apps: [
    {
      name: 'skidchecker',
      script: 'src/server.js',
      cwd: __dirname,
      interpreter: 'node',
      env: {
        NODE_ENV: 'production',
        HOST: '0.0.0.0',
        PORT: 3000
      }
    }
  ]
};