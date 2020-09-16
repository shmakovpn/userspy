/*
 * userspy project spy/static/spy/app.js
 * Author: shmakovpn <shmakovpn@yandex.ru>
 * Date: 2020-08-12
 */
// utils

// format datetime from database timestamp format to human format
function formatDatetime(datetime) {
    let datetimeArray = datetime.split(' ');
    return `${datetimeArray[0].split('-').reverse().join('.')} ${datetimeArray[1].slice(0,8)}`;
}

// converts status: str to name of icon: str
function statusToIcon(status) {
    if(status === 'No ping') {
        return 'skull';
    } else if(status === 'Error') {
        return 'bug';
    } else if(status === 'Red') {
        return 'red-circle';
    } else if(status === 'Yellow') {
        return 'yellow-circle';
    } else if(status === 'Green') {
        return 'green-circle';
    } else if(status === 'Unknown') {
        return 'help';
    }
    return 'bug';
}

// converts status: str to index of icon: int
function statusToIndex(status) {
    if(status === 'No ping') {
        return 9;
    } else if(status === 'Error') {
        return 8;
    } else if(status === 'Red') {
        return 7;
    } else if(status === 'Yellow') {
        return 6;
    } else if(status === 'Green') {
        return 5;
    } else if(status === 'Unknown') {
        return 1;
    }
    return 8;
}

function validateIpAddress(ipaddress) {  
    if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipaddress)) {  
        return (true)  
    }  
    return (false)  
}

// make #active-tasks-list a sortable dataTable
function activeTasksListDataTable() {
    $('#active-tasks-list table.table').DataTable({
        'retrieve': true,
        'searching': false,
        'paging': false,
        'info': false,
        'columns': [
            {'data': 'ip'},
            {'data': 'desc'},
            {
                'data': 'status',
                'render': function(data, type, row) {
                    return `<span style="display: none">${statusToIndex(data)}</span><ion-icon name="${statusToIcon(data)}" style="vertical-align: middle" role="img" class="md hydrated" aria-label="grid"></ion-icon>`;
                }
            },
            {
                'data': 'deadline',
                'render': function(data, type, row) {
                    return formatDatetime(data);
                }
            },
            {
                'data': 'created',
                'render': function(data, type, row) {
                    return formatDatetime(data);
                }
            },
            {
                'data': 'actions',
                'render': function(data, type, row) {
                    return `<ion-icon name="trash" style="vertical-align: middle" role="img" class="md hydrated" aria-label="grid" onclick="onDeleteTask(${data})"></ion-icon>`;
                }
            }
        ]
    });
    $('.dataTables_length').addClass('bs-select');
}

// loader
function showLoader() {
    $('div.loader').show();  // show loader
    $('div.content-items').hide();  // hide content items
}

function hideLoader() {
    $('div.loader').hide();  // hide loader
    $('div.content-items').show();  // show content items
}

// heartbeat indicator
function showNoHeartbeat() {
    hideLoader();  // 
    $('#no-heartbeat').show();
    $('#active-tasks-list').hide();
    $('#no-active-tasks').hide();
}

function hideNoHeartbeat() {
    $('#no-heartbeat').hide();
}

//

function hideContentItems() {
    $('div.content-item').hide();  // hide all of content items
}

function showActiveTasks() {
    hideContentItems();  // hide all of content items
    $('#active-tasks').show();  // show active tasks
}

function showAddTaskForm() {
    hideContentItems();  // hide all of content items
    $('#add-task-form').show();  // show add a task form
}

// updates active tasks list
function updateActiveTasks() {
    showLoader();  // show loader and hide content items
    $.ajax({
        url: '/tasks/',
        cache: false,
        type: 'GET',
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('updateActiveTasks failed');
            console.log(jqXHR);
            console.log(textStatus);
            console.log(errorThrown);
        },
        success: function(data, textStatus, jqXHR) {
            try {
                let responseJSON = JSON.parse(data);
                if(responseJSON.success === true) {
                    hideNoHeartbeat();  // hide *no heartbeat* indicator if it shown
                    let activeTasks = responseJSON.active_tasks;
                    if(activeTasks.length === 0) {
                        $('#no-active-tasks').show();
                        $('#active-tasks-list').hide();
                    } else {
                        $('#no-active-tasks').hide();
                        $('#active-tasks-list').show();
                        $('#active-tasks-list table.table')
                            .DataTable()
                            .clear()
                            .rows.
                            add(
                                activeTasks.map(activeTask => Object.assign(activeTask, {'actions': activeTask.id}))
                            ).draw();
                    }
                    hideLoader();  // hide loader and show content items
                } else {
                    if('heartbeat' in responseJSON && responseJSON.heartbeat === false) {
                        showNoHeartbeat();  // hide *loader* and show *no hearbeat* indicator
                    } else {
                        console.log(`updateActiveTasks success===false; ${responseJSON.message}`);
                    }
                }
            } catch(e) {
                console.log('updateActiveTasks failed, response could not be parsed as JSON');
            }
        }
    });
}

function submitAddTask() {
    let ip = $('#add-task-ip').val();
    let desc = $('#add-task-desc').val();
    if(!validateIpAddress(ip)) {
        alert('Invalid IP address!');
        return;
    }
    $.ajax({
        url: '/add/',
        cache: false,
        type: 'POST',
        contentType: 'application/json; charset=utf-8',
        headers: {'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val()},
        dateType: 'text',
        data: JSON.stringify({
            'ip': ip,
            'desc': desc
        }),
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('submit add task error');
            console.log(jqXHR);
            console.log(textStatus);
            console.log(errorThrown);
        },
        success: function(data, textStatus, jqXHR) {
            try {
                let responseJSON = JSON.parse(data);
                if(responseJSON.success === true) {
                    updateActiveTasks();
                    console.log('submit add task success===true');
                } else {
                    console.log(`submit add task success===false; ${responseJSON.message}`);
                }
            } catch(e) {
                console.log('submit add task failed, response could not be parsed as JSON');
            }
        }
    });
    // clear "Add task form"
    $('#add-task-ip').val('');
    $('#add-task-desc').val('');
    showActiveTasks();
}

function deleteTask(id) {
    $.ajax({
        url: '/delete/',
        cache: false,
        type: 'POST',
        contentType: 'application/json; charset=utf-8',
        headers: {'X-CSRFToken': $('input[name=csrfmiddlewaretoken]').val()},
        dateType: 'text',
        data: JSON.stringify({
            'id': id
        }),
        error: function(jqXHR, textStatus, errorThrown) {
            console.log('delete task error');
            console.log(jqXHR);
            console.log(textStatus);
            console.log(errorThrown);
        },
        success: function(data, textStatus, jqXHR) {
            try {
                let responseJSON = JSON.parse(data);
                if(responseJSON.success === true) {
                    updateActiveTasks();
                    console.log('delete task success===true');
                } else {
                    console.log(`delete task success===false; ${responseJSON.message}`);
                }
            } catch(e) {
                console.log('delete task failed, response could not be parsed as JSON');
            }
        }
    });
}

function autoUpdateActiveTasks() {
    setTimeout(autoUpdateActiveTasks, 20000);
    if($('#active-tasks').css('display')!=='none') {
        updateActiveTasks();
    }
}

function cancelAddTask() {
    showActiveTasks();
}

// event handlers
function onUpdateBtn(event) {
    updateActiveTasks();
}

function onAddBtn(event) {
    showAddTaskForm();
}

function onAddTaskSubmitBtn(event) {
    submitAddTask();
}

function onAddTaskCancelBtn(event) {
    cancelAddTask();
}

function onDeleteTask(id) {
    deleteTask(id);
}
// end event handlers

// document onReady handler
$(function() {
    // makes nav-bar buttons show that they are being clicked
    $('.nav-item').click(function(event) {
        $(this).addClass('nav-item-clicked');
        setTimeout(function() {
            $('.nav-item-clicked').removeClass('nav-item-clicked');
        }, 300);
    });
    // add event handlers to buttons of the nav-bar
    $('#update-btn a').click(onUpdateBtn);  // the Update button of the nav-bar
    $('#add-btn a').click(onAddBtn);  // the Add button of the nav-bar
    // add event handlers to "add task form" buttons
    $('#add-task-submit').click(onAddTaskSubmitBtn);
    $('#add-task-cancel').click(onAddTaskCancelBtn);
    activeTasksListDataTable();
    showActiveTasks();
    updateActiveTasks();
    autoUpdateActiveTasks();  // starting auto updating active tasks
});
