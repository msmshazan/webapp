const MiniCssExtractPlugin = require("mini-css-extract-plugin");
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');

module.exports = {
  devtool: 'inline-source-map',
    entry:{
      main: './js/application.js',
      vendor: './js/vendor.js',
    },
    watchOptions: {
      ignored: [/node_modules/,/.vscode/]
    },
    mode:'development',
    plugins: [
        new MiniCssExtractPlugin() , 
        new HtmlWebpackPlugin({ hash:true,title: 'Test Application',template: './index.html',}),
        new CleanWebpackPlugin()
      ],
    module: {
        rules: [
          {
                     test: /\.(png|svg|jpg|ico|gif)$/,
                     use: [
                       'file-loader',
                     ],
                   },
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