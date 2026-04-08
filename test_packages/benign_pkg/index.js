module.exports = {
  capitalize: function(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  },
  reverse: function(str) {
    return str.split('').reverse().join('');
  },
  repeat: function(str, count) {
    return str.repeat(count);
  }
};
