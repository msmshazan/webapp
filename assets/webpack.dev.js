const merge = require('webpack-merge');
const common = require('./webpack.common.js');
const TerserPlugin = require('terser-webpack-plugin');
const OptimizeCSSAssetsPlugin = require('optimize-css-assets-webpack-plugin');
const MiniCssExtractPlugin = require("mini-css-extract-plugin");

module.exports =merge(common, {
  mode: 'development',
  plugins:[new MiniCssExtractPlugin({
    // Options similar to the same options in webpackOptions.output
    // both options are optional
    filename:  '[name].bundle.css',
    chunkFilename: '[id].bundle.css',
  })],
  optimization: {
    minimize: false,
    minimizer: [new TerserPlugin(), new OptimizeCSSAssetsPlugin({ cssProcessorOptions: {
      map: {
        inline: true
      }
    }})],
  },
  module:{
    rules:[
      {
        test: /\.(png|svg|jpg|ico|gif)$/,
        use: [{
          loader:'file-loader',
          options: {
           name: '[name].[ext]',
          }
        }
        ],
      },
    ]
  },
  devtool: 'inline-source-map',
      output: {
      filename: '[name].bundle.js'
    }
  });