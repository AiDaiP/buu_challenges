function deEquation(str) {
  // 需执行两次以处理所有的 jsfuck 下标
  for (let i = 0; i <= 1; i++) {
    str = str.replace(/l\[(\D*?)](\+l|-l|==)/g, (m, a, b) => 'l[' + eval(a) + ']' + b)
  }
 
  // 处理 == 后的 jsfuck
  str = str.replace(/==(\D*?)&&/g, (m, a) => '==' + eval(a) + '&&')
 
  return str
}
