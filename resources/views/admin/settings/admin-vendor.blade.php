@extends('admin.layout.layout')

@section('content')

    <section class="content">
        <div class="container-fluid">

            <div class="row clearfix">
                <div class="col-lg-12 col-md-12 col-sm-12 col-xs-12">
                    @if(\Illuminate\Support\Facades\Session::has('error_message'))
                        <div class="alert alert-danger alert-dismissible" role="alert">
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                            <strong>Error: </strong> {{ \Illuminate\Support\Facades\Session::get('error_message') }}
                        </div>
                    @endif
                    @if(\Illuminate\Support\Facades\Session::has('neutral_message'))
                        <div class="alert alert-info alert-dismissible" role="alert">
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                            <strong>Notice: </strong> {{ \Illuminate\Support\Facades\Session::get('neutral_message') }}
                        </div>
                    @endif
                    @if(\Illuminate\Support\Facades\Session::has('success_message'))
                        <div class="alert alert-success alert-dismissible" role="alert">
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                            <strong>Success: </strong> {{ \Illuminate\Support\Facades\Session::get('success_message') }}
                        </div>
                    @endif
                    @if($errors->any())
                        <div class="alert alert-danger alert-dismissible" role="alert">
                            <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                            <strong>Error: </strong>
                            <br>
                            @foreach($errors->all() as $error)
                                &emsp; &#x2022; {{ $error }}<br>
                            @endforeach
                        </div>
                    @endif
                </div>
            </div>

            <form action="{{ url('/admin/account') }}" method="POST" id="updateAdminDetails" name="updateAdminDetails" enctype="multipart/form-data">
                @csrf
                <!-- Basic Table -->
                <div class="row clearfix">
                    <div class="col-lg-12 col-md-12 col-sm-12 col-xs-12">
                        <div class="card">
                            <div class="header">
                                <h2>
                                    APPROVE VENDORS
                                </h2>
                            </div>
                            <div class="body table-responsive">
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th style="text-align: center;">#</th>
                                            <th style="text-align: center;">VENDOR</th>
                                            <th style="text-align: center;">STATUS</th>
                                            <th style="text-align: center;">ACTION</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @foreach ($userDetails as $user)
                                            <tr>
                                                <th scope="row" style="text-align: center;">{{ $loop->iteration }}</th>
                                                <td style="text-align: center;">{{ ucwords($user['name']) }}</td>
                                                <td style="text-align: center;">
                                                    @if($user['status'] == 1)
                                                        <button type="button" class="btn btn-success waves-effect" style="width: 100px; pointer-events: none;">Active</button>
                                                    @elseif ($user['status'] == 0)
                                                        <button type="button" class="btn btn-danger waves-effect" style="width: 100px; pointer-events: none;">Deactivated</button>
                                                    @endif
                                                </td>
                                                <td style="text-align: center;">
                                                    @if($user['vendor_update_status'] == 1)
                                                        <button type="button" class="btn btn-primary waves-effect" data-toggle="modal" data-target="#{{ $loop->iteration }}" style="width: 100px; @if($user['status'] == 0) pointer-events: none @endif">@if($user['status'] == 0) Can't @endif Update</button>
                                                    @elseif ($user['vendor_update_status'] == 0)
                                                        <button type="button" class="btn btn-default waves-effect" style="width: 100px; pointer-events: none;">No Updates</button>
                                                    @endif
                                                </td>
                                            </tr>
                                            <div class="modal fade" id="{{ $loop->iteration }}" tabindex="-1" role="dialog">
                                                <div class="modal-dialog modal-lg" role="document">
                                                    <div class="modal-content">
                                                        <div class="modal-header">
                                                            <h4 class="modal-title" id="{{ $loop->iteration }}">{{ ucwords($user['name']) }}</h4>
                                                        </div>
                                                        <div class="modal-body">
                                                            <div class="table-responsive">
                                                                <div class="row">
                                                                    <div class="col">Column Heading 1</div>
                                                                    <div class="col">Column Heading 2</div>
                                                                    <!-- Add more column headings as needed -->
                                                                </div>
                                                                <div class="row">
                                                                    <div class="col">1</div>
                                                                    <div class="col">2</div>
                                                                    <!-- Add more data values as needed -->
                                                                </div>
                                                            </div>
                                                        </div>
                                                        <div class="modal-footer">
                                                            <button type="button" class="btn btn-success waves-effect">Approve</button>
                                                            <button type="button" class="btn btn-danger waves-effect" data-dismiss="modal">Deny</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            @endforeach
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- #END# Basic Table -->
            </form>
        </div>
    </section>

@endsection