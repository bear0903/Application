/**
 * Jquery Validate Error Message
 */

jQuery.extend(jQuery.validator.messages, {
    required: "此栏位必须输入.",
    remote: "Please fix this field.",
    email: "请输入一个有效的邮件地址Please enter a valid email address.",
    url: "请输入一个有效的URL,Please enter a valid URL.",
    date: "请输入一个有效的日期.",
    dateISO: "请输入一个有效的日期 (ISO).",
    number: "请输入一个有效的数字.",
    digits: "请输入数字Please enter only digits.",
    creditcard: "请输入正确的信用卡号Please enter a valid credit card number.",
    equalTo: "请再次输入同样的值.",
    accept: "请输入一个值带有有效的扩展Please enter a value with a valid extension.",
    maxlength: jQuery.validator.format("请输入不超过 {0} 个字符 Please enter no more than {0} characters."),
    minlength: jQuery.validator.format("请至少输入 {0} 个字符 Please enter at least {0} characters."),
    rangelength: jQuery.validator.format("Please enter a value between {0} and {1} characters long."),
    range: jQuery.validator.format("Please enter a value between {0} and {1}."),
    max: jQuery.validator.format("Please enter a value less than or equal to {0}."),
    min: jQuery.validator.format("Please enter a value greater than or equal to {0}.")
});