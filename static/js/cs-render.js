function getCsFromLs() {
    let localStorageCs = localStorage.getItem('cs');

    if (!localStorageCs)  {
        return false;
    };
    return localStorageCs;
};

function deployCsToLs(cs) {
    localStorage.setItem('cs', cs);
    deployCsLink()
}

function getCsFromSys() {
    if(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dk';
    };
    return 'lt';
};

function deployCsLink() {
    /* Takes in the cs that needs to be deployed */

    ejectCsLink()

    let cs = getCsFromLs();
    
    let csLink = document.createElement('link');
    csLink.classList.add('cs-lk');
    csLink.rel = 'stylesheet';
    csLink.href = `/static/css/cs-${cs}.css`;

    document.head.appendChild(csLink);
}

function ejectCsLink() {
    /* Ejects all cs-lk */
    let csLink = document.querySelector('link[rel="stylesheet"].cs-lk');
    
    try {
        document.head.removeChild(csLink);
    } catch(e) {
        if (e.message != 'Failed to execute \'removeChild\' on \'Node\': parameter 1 is not of type \'Node\'.' && !(e instanceof TypeError)) {
            throw(e)
        }
    }
}

function loadCs() {
    let currentCs = getCsFromLs();

    if (!currentCs) { // If no cs settings is set in ls then...
        currentCs = getCsFromSys()
    }

    deployCsToLs(currentCs)

    /* currentCs = 'dk' ? 'lt' : 'dk';
    if (!currentCs) {
        currentCs = getCsFromSys();
    }

    deployCsToLs(currentCs); */
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    deployCsToLs(e.matches ? 'dk' : 'lt')
});

document.addEventListener("DOMContentLoaded", loadCs())

/* 
1. Test whether if there is cs data in local storage
2. If so load that cs.
3. Else get the systems preferred cs - 
    a) Update local storage with that cs
    b) Load cs from local storage 
 */