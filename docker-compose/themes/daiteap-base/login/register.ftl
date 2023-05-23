<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('firstName','lastName','email','username','password','password-confirm'); section>
    <#if section = "header">
        ${msg("registerTitle")}
    <#elseif section = "form">
        <form id="kc-register-form" class="${properties.kcFormClass!}" action="${url.registrationAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="firstName" class="${properties.kcLabelClass!}">${msg("firstName")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="firstName" class="${properties.kcInputClass!}" name="firstName"
                           value="${(register.formData.firstName!'')}"
                           aria-invalid="<#if messagesPerField.existsError('firstName')>true</#if>"
                    />

                    <#if messagesPerField.existsError('firstName')>
                        <span id="input-error-firstname" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('firstName'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="lastName" class="${properties.kcLabelClass!}">${msg("lastName")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="lastName" class="${properties.kcInputClass!}" name="lastName"
                           value="${(register.formData.lastName!'')}"
                           aria-invalid="<#if messagesPerField.existsError('lastName')>true</#if>"
                    />

                    <#if messagesPerField.existsError('lastName')>
                        <span id="input-error-lastname" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('lastName'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="email" class="${properties.kcLabelClass!}">${msg("email")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="email" class="${properties.kcInputClass!}" name="email"
                           value="${(register.formData.email!'')}" autocomplete="email"
                           aria-invalid="<#if messagesPerField.existsError('email')>true</#if>"
                    />

                    <#if messagesPerField.existsError('email')>
                        <span id="input-error-email" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('email'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>

            <#if !realm.registrationEmailAsUsername>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="username" class="${properties.kcLabelClass!}">${msg("username")}</label>
                    </div>
                    <div class="${properties.kcInputWrapperClass!}">
                        <input type="text" id="username" class="${properties.kcInputClass!}" name="username"
                               value="${(register.formData.username!'')}" autocomplete="username"
                               aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                        />

                        <#if messagesPerField.existsError('username')>
                            <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('username'))?no_esc}
                            </span>
                        </#if>
                    </div>
                </div>
            </#if>

            <#if passwordRequired??>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>
                    </div>
                    <div class="${properties.kcInputWrapperClass!}">
                        <input type="password" id="password" class="${properties.kcInputClass!}" name="password"
                               autocomplete="new-password"
                               aria-invalid="<#if messagesPerField.existsError('password','password-confirm')>true</#if>"
                        />

                        <#if messagesPerField.existsError('password')>
                            <span id="input-error-password" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('password'))?no_esc}
                            </span>
                        </#if>
                    </div>
                </div>

                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="password-confirm"
                               class="${properties.kcLabelClass!}">${msg("passwordConfirm")}</label>
                    </div>
                    <div class="${properties.kcInputWrapperClass!}">
                        <input type="password" id="password-confirm" class="${properties.kcInputClass!}"
                               name="password-confirm"
                               aria-invalid="<#if messagesPerField.existsError('password-confirm')>true</#if>"
                        />

                        <#if messagesPerField.existsError('password-confirm')>
                            <span id="input-error-password-confirm" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('password-confirm'))?no_esc}
                            </span>
                        </#if>
                    </div>
                </div>

                <div id="popover-password">
                    <p><span id="result"></span></p>
                    <div class="progress">
                        <div id="password-strength" 
                            class="progress-bar" 
                            role="progressbar" 
                            aria-valuenow="40" 
                            aria-valuemin="0" 
                            aria-valuemax="100" 
                            style="width:0%">
                        </div>
                    </div>
                </div>

                <script type="text/javascript">
                    let state = false;
                    let password = document.getElementById("password");
                    let passwordStrength = document.getElementById("password-strength");
                    let lowUpperCase = document.querySelector(".low-upper-case i");
                    let number = document.querySelector(".one-number i");
                    let specialChar = document.querySelector(".one-special-char i");
                    let eightChar = document.querySelector(".eight-character i");

                    password.addEventListener("keyup", function(){
                        let pass = document.getElementById("password").value;
                        checkStrength(pass);
                    });

                    function toggle(){
                        if(state){
                            document.getElementById("password").setAttribute("type","password");
                            state = false;
                        }else{
                            document.getElementById("password").setAttribute("type","text")
                            state = true;
                        }
                    }

                    function myFunction(show){
                        show.classList.toggle("fa-eye-slash");
                    }

                    function checkStrength(password) {
                        let strength = 0;

                        //If password contains both lower and uppercase characters
                        if (password.match(/([a-z].*[A-Z])|([A-Z].*[a-z])/)) {
                            strength += 1;
                        }
                        //If it has numbers and characters
                        if (password.match(/([0-9])/)) {
                            strength += 1;
                        }
                        //If it has one special character
                        if (password.match(/([!,%,&,@,#,$,^,*,?,_,~])/)) {
                            strength += 1;
                        }
                        //If password is greater than 7
                        if (password.length > 7) {
                            strength += 1;
                        }

                        // If value is less than 2
                        if (strength < 2) {
                            passwordStrength.classList.remove('progress-bar-warning');
                            passwordStrength.classList.remove('progress-bar-success');
                            passwordStrength.classList.add('progress-bar-danger');
                            passwordStrength.style = 'width: 10%';
                        } else if (strength == 3) {
                            passwordStrength.classList.remove('progress-bar-success');
                            passwordStrength.classList.remove('progress-bar-danger');
                            passwordStrength.classList.add('progress-bar-warning');
                            passwordStrength.style = 'width: 60%';
                        } else if (strength == 4) {
                            passwordStrength.classList.remove('progress-bar-warning');
                            passwordStrength.classList.remove('progress-bar-danger');
                            passwordStrength.classList.add('progress-bar-success');
                            passwordStrength.style = 'width: 100%';
                        }
                    }
                </script>
            </#if>

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label class="${properties.kcLabelClass!}">${msg("By creating a Daiteap Account, you agree on our Terms & Conditions and have read and acknowledge the Global Privacy Statement")}</label>
                </div>
                
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcInputWrapperClass!}">
                    <input
                        type="checkbox"
                        id="user.attributes.no_news"
                        class="${properties.kcInputClassCheckboxInput!}"
                        name="user.attributes.no_news"
                        value="${(register.formData['user.attributes.no_news']!'')}"
                    />
                    <label for="user.attributes.no_news" class="${properties.kcInputClassCheckboxLabel!}">${msg("I don't want to recieve updates and news of Daiteap.com")}</label>
                </div>
            </div>

            <#if recaptchaRequired??>
                <div class="form-group">
                    <div class="${properties.kcInputWrapperClass!}">
                        <div class="g-recaptcha" data-size="compact" data-sitekey="${recaptchaSiteKey}"></div>
                    </div>
                </div>
            </#if>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                        <span><a href="${url.loginUrl}">${kcSanitize(msg("backToLogin"))?no_esc}</a></span>
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doRegister")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>