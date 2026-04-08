module.exports = {
  encrypt: function(data) {
    return Buffer.from(data).toString('base64');
  },
  decrypt: function(data) {
    return Buffer.from(data, 'base64').toString('utf8');
  }
};
