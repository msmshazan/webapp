const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');

module.exports = {
    mode:'none',
    entry:{
      index: ['./js/index.js'],
      admin: ['./js/admin.js'],
      signup: ['./js/signup.js'],
      login: ['./js/login.js'],
    },
    watchOptions: {
      ignored: [/node_modules/,/.vscode/]
    },
    plugins: [
        new HtmlWebpackPlugin({hash:true,title: 'Index Page',template: './template/index.html' ,filename: 'index.html', chunks :['index']}),
        new HtmlWebpackPlugin({hash:true,title: 'Login Page',template: './template/login.html', filename: 'login.html', chunks :['login']}),
        new HtmlWebpackPlugin({hash:true,title: 'Admin Page',template: './template/admin.html', filename: 'admin.html', chunks :['admin']}),
        new HtmlWebpackPlugin({hash:true,title: 'Signup Page',template: './template/signup.html', filename: 'signup.html', chunks :['signup']}),
        new CleanWebpackPlugin(),
         ],
    module: {
        rules: [
            {
                test: /\.css$/,
                exclude: [/node_modules/,/.vscode/],
                use: [
                    {
                        loader: MiniCssExtractPlugin.loader,
                    },
                  {
                    loader: 'css-loader',
                    options: {
                      importLoaders: 1,
                    }
                  },
                  {
                    loader: 'postcss-loader'
                  }
                ]
              }
        ]
      }
  };