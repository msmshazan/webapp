const merge = require('webpack-merge');
const common = require('./webpack.common.js');
const TerserPlugin = require('terser-webpack-plugin');
const OptimizeCSSAssetsPlugin = require('optimize-css-assets-webpack-plugin');
const MiniCssExtractPlugin = require("mini-css-extract-plugin");

module.exports = merge(common,{
    devtool: 'source-map',
    mode: 'production',
    plugins:[new MiniCssExtractPlugin({
      // Options similar to the same options in webpackOptions.output
      // both options are optional
      filename:  '[name].[hash].css',
      chunkFilename: '[id].[hash].css',
    })],
    module:{
      rules:[
        {
          test: /\.(png|svg|jpg|ico|gif)$/,
          use: [{
            loader:'file-loader',
          }
          ],
        },
      ]
    },
    optimization: {
      minimize: true,
      minimizer: [new TerserPlugin(), new OptimizeCSSAssetsPlugin({ cssProcessorOptions: {
        map: {
          inline: false,
          annotation: true,
        }
      }})],
    },
    output: {
      filename: '[name].[contentHash].bundle.js'
    }
  });