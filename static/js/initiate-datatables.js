// Initiate datatables in roles, tables, users page

function initDataTable(selector) {
    $(selector).DataTable({
        responsive: true,
        pageLength: 20,
        lengthChange: false,
        searching: true,
        ordering: true
    });
}


