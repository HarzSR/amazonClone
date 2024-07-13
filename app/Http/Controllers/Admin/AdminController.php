<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Http\Requests\StoreAdminRequest;
use App\Http\Requests\UpdateAdminRequest;
use App\Models\Admin\Admin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\File;
use Intervention\Image\Facades\Image;
use Illuminate\Support\Facades\Session;

class AdminController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    
    public function index()
    {
        //

        Session::put('page', 'dashboard');

        if (Auth::guard('admin')->user()->type == "admin")
        {
            return view('admin.dashboard');
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            return view('admin.dashboard');
        }
        else if  (Auth::guard('admin')->user()->type == "vendor")
        {
            return view('admin.dashboard');
        }
        else
        {
            Auth::guard('admin')->logout();
 
            Session::flush();

            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }
    }

    /**
     * Show the form for creating a new resource.
     */

    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */

    public function store(StoreAdminRequest $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */

    public function show(Admin $admin)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */

    public function edit(Admin $admin)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */

    public function update(UpdateAdminRequest $request, Admin $admin)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */

    public function destroy(Admin $admin)
    {
        //
    }

    /**
     * Login function
     * 
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View|\Illuminate\Http\RedirectResponse
     */

    public function login(Request $request)
    {
        if($request->isMethod('POST'))
        {
            $data = $request->all();

            $rules = [
                'email' => 'required|email|max:255',
                'password' => 'required|min:8',
            ];
            $customMessages = [
                'email.required' => 'Email is required',
                'email.email' => 'The email must be a valid email address.',
                'email.max' => 'The email is too long, please try a different email address.',
                'password.required' => 'Password is required',
                'password.min' => 'The password is incorrect and short.',
            ];

            $this->validate($request, $rules, $customMessages);

            if(Auth::guard('admin')->attempt(['email' => $data['email'], 'password' => $data['password'], 'status' => 1]))
            {
                return redirect('/admin/dashboard');
            }
            elseif(Auth::guard('admin')->attempt(['email' => $data['email'], 'password' => $data['password'], 'status' => 0]))
            {
                if (Auth::guard('admin')->user()->type == "vendor")
                {
                    Session::put('additional_message', 'logout');
                    return redirect('/admin/error/201')->with('error_message', 'User Disabled. Please contact Administrator.');
                }
                return redirect('/admin/error/201')->with('error_message', 'User Disabled. Opening Dashboard with Limited Privilage.');
            }
            else
            {
                return redirect()->back()->with('error_message', 'Invalid Email or Password')->withInput($request->input());
            }
        }

        return view('admin.login');
    }

    /**
     * 
     */

    public function password(Request $request)
    {
        Session::put('page', 'passwords');

        if (Auth::guard('admin')->user()->type == "admin" || Auth::guard('admin')->user()->type == "sub-admin" || Auth::guard('admin')->user()->type == "vendor")
        {
            if($request->isMethod('POST'))
            {
                $data = $request->all();

                $rules = [
                    'current_password' => 'required|min:8',
                    'new_password' => 'required|min:8',
                    'confirm_password' => 'required|min:8',
                ];
                $customMessages = [
                    'current_password.required' => 'Current password is required',
                    'current_password.min' => 'The current password is incorrect and short.',
                    'new_password.required' => 'New password is required',
                    'new_password.min' => 'The new password is incorrect and short.',
                    'confirm_password.required' => 'Confirm password is required',
                    'confirm_password.min' => 'The confirm password is incorrect and short.',
                ];

                $this->validate($request, $rules, $customMessages);

                if (Hash::check($data['current_password'], Auth::guard('admin')->user()->password))
                {
                    if ($data['current_password'] == $data['new_password'])
                    {
                        return redirect()->back()->with('error_message', 'New password can\'t be the same as current password');
                    }
                    else if ($data['new_password'] != $data['confirm_password'])
                    {
                        return redirect()->back()->with('error_message', 'New password and Confirm password are not same');
                    }
                    else
                    {
                        Admin::where('id', Auth::guard('admin')->user()->id)->update(['password' => bcrypt($data['new_password'])]);

                        return redirect()->back()->with('success_message', 'Password update Successful');
                    }
                }
                else
                {
                    return redirect()->back()->with('error_message', 'Current password is Incorrect');
                }
            }
        }

        return view('admin.settings.admin-password');
    }

    /**
     * Update Admin Details
     *
     * @param Request $request
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View|\Illuminate\Http\RedirectResponse
     * @throws \Illuminate\Validation\ValidationException
     */

    public function account(Request $request)
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            Session::put('page', 'accounts');
 
            $userDetails = Admin::where('email', Auth::guard('admin')->user()->email)->first()->toArray();
     
            if($request->isMethod('POST'))
            {
                $data = $request->all();
     
                $rules = [
                    'name' => 'nullable|min:3|regex:/^[-_ a-zA-Z0-9]+$/',
                    'number' => 'nullable|min:8|regex:/^([0-9\s\-\+\(\)]*)$/',
                    'adminImage' => 'nullable|mimes:jpeg,jpg,png',
                    'note' => 'nullable|min:3|max:2048|regex:/^[-_ a-zA-Z0-9]+$/'
                ];
                $customMessages = [
                    'name.min' => 'The name is too short.',
                    'name.regex' => 'The name has unauthorised characters.',
                    'number.min' => 'The number is too short.',
                    'number.regex' => 'The number is in invalid format.',
                    'adminImage.mimes' => 'Invalid image format. Allowed: jpeg, jpg, png.',
                    'note.min' => 'Note is too short. Please type more.',
                    'note.max' => 'Note is too large. Please reduce size to 2000 characters.',
                    'note.regex' => 'The note is in invalid format.',
                ];
     
                $this->validate($request, $rules, $customMessages);
     
                $image = 0;
                $name = 0;
                $number = 0;
                $note = 0;
     
                if($request->hasFile('adminImage'))
                {
                    $image_tmp = $request->file('adminImage');
     
                    if ($image_tmp->isValid())
                    {
                        $extension = $image_tmp->getClientOriginalExtension();
                        $imageName = time() . mt_rand() . '.' . $extension;
    
                        $folderPath = 'admin/images/admin_images/';
    
                        if (!File::exists($folderPath)) 
                        {
                            File::makeDirectory($folderPath);
                        }
     
                        $imagePath = 'admin/images/admin_images/' . $imageName;
     
                        Image::make($image_tmp)->resize(300, 400)->save($imagePath);
                    }
     
                    $image = 1;
     
                }
     
                if($request->has('name') && $data['name'] != '' && $userDetails['name'] != $data['name'])
                {
                    $name = 1;
                }
     
                if($request->has('number') && $data['number'] != '' && $userDetails['phone'] != $data['number'])
                {
                    $number = 1;
                }
     
                if($request->has('note') && $data['note'] != '' && $userDetails['notes'] != $data['note'])
                {
                    $note = 1;
                }
     
                if($image == 0 && $name == 0 && $number == 0 && $note == 0)
                {
                    return redirect()->back()->with('neutral_message', 'No updates were made.');
                }
                else if($image == 0 && $name == 0 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User notes updated');
                }
                else if($image == 0 && $name == 0 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['phone' => $data['number']]);
     
                    return redirect()->back()->with('success_message', 'User number updated');
                }
                else if($image == 0 && $name == 0 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['phone' => $data['number'], 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User number & notes updated');
                }
                else if($image == 0 && $name == 1 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name']]);
     
                    return redirect()->back()->with('success_message', 'User name updated');
                }
                else if($image == 0 && $name == 1 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name'], 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User name & notes updated');
                }
                else if($image == 0 && $name == 1 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name'], 'phone' => $data['number']]);
     
                    return redirect()->back()->with('success_message', 'User name & number updated');
                }
                else if($image == 0 && $name == 1 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name'], 'phone' => $data['number'], 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User name, number & notes updated');
                }
                else if($image == 1 && $name == 0 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName]);
     
                    return redirect()->back()->with('success_message', 'User image was updated');
                }
                else if($image == 1 && $name == 0 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User image & notes updated');
                }
                else if($image == 1 && $name == 0 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'phone' => $data['number']]);
     
                    return redirect()->back()->with('success_message', 'User image & number updated');
                }
                else if($image == 1 && $name == 0 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'phone' => $data['number'], 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User image, number & notes updated');
                }
                else if($image == 1 && $name == 1 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name']]);
     
                    return redirect()->back()->with('success_message', 'User image & name updated');
                }
                else if($image == 1 && $name == 1 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name'], 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User image, name & notes updated');
                }
                else if($image == 1 && $name == 1 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name'], 'phone' => $data['number']]);
     
                    return redirect()->back()->with('success_message', 'User name, number & number updated');
                }
                else if($image == 1 && $name == 1 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name'], 'phone' => $data['number'], 'notes' => $data['note']]);
     
                    return redirect()->back()->with('success_message', 'User details updated');
                }
                else
                {
                    return redirect()->back()->with('error_message', 'Invalid data, please try again')->withInput($request->input());
                }
            }
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            Session::put('page', 'accounts');
 
            $userDetails = Admin::where('email', Auth::guard('admin')->user()->email)->first()->toArray();
    
            if($request->isMethod('POST'))
            {
                $data = $request->all();
    
                $rules = [
                    'name' => 'nullable|min:3|regex:/^[-_ a-zA-Z0-9]+$/',
                    'number' => 'nullable|min:8|regex:/^([0-9\s\-\+\(\)]*)$/',
                    'adminImage' => 'nullable|mimes:jpeg,jpg,png',
                    'note' => 'nullable|min:3|max:2048|regex:/^[-_ a-zA-Z0-9]+$/'
                ];
                $customMessages = [
                    'name.min' => 'The name is too short.',
                    'name.regex' => 'The name has unauthorised characters.',
                    'number.min' => 'The number is too short.',
                    'number.regex' => 'The number is in invalid format.',
                    'adminImage.mimes' => 'Invalid image format. Allowed: jpeg, jpg, png.',
                    'note.min' => 'Note is too short. Please type more.',
                    'note.max' => 'Note is too large. Please reduce size to 2000 characters.',
                    'note.regex' => 'The note is in invalid format.',
                ];
    
                $this->validate($request, $rules, $customMessages);
    
                $image = 0;
                $name = 0;
                $number = 0;
                $note = 0;
    
                if($request->hasFile('adminImage'))
                {
                    $image_tmp = $request->file('adminImage');
    
                    if ($image_tmp->isValid())
                    {
                        $extension = $image_tmp->getClientOriginalExtension();
                        $imageName = time() . mt_rand() . '.' . $extension;

                        $folderPath = 'admin/images/admin_images/';

                        if (!File::exists($folderPath)) 
                        {
                            File::makeDirectory($folderPath);
                        }
    
                        $imagePath = 'admin/images/admin_images/' . $imageName;
    
                        Image::make($image_tmp)->resize(300, 400)->save($imagePath);
                    }
    
                    $image = 1;
    
                }
    
                if($request->has('name') && $data['name'] != '' && $userDetails['name'] != $data['name'])
                {
                    $name = 1;
                }
    
                if($request->has('number') && $data['number'] != '' && $userDetails['phone'] != $data['number'])
                {
                    $number = 1;
                }
    
                if($request->has('note') && $data['note'] != '' && $userDetails['notes'] != $data['note'])
                {
                    $note = 1;
                }
    
                if($image == 0 && $name == 0 && $number == 0 && $note == 0)
                {
                    return redirect()->back()->with('neutral_message', 'No updates were made.');
                }
                else if($image == 0 && $name == 0 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User notes updated');
                }
                else if($image == 0 && $name == 0 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['phone' => $data['number']]);
    
                    return redirect()->back()->with('success_message', 'User number updated');
                }
                else if($image == 0 && $name == 0 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['phone' => $data['number'], 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User number & notes updated');
                }
                else if($image == 0 && $name == 1 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name']]);
    
                    return redirect()->back()->with('success_message', 'User name updated');
                }
                else if($image == 0 && $name == 1 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name'], 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User name & notes updated');
                }
                else if($image == 0 && $name == 1 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name'], 'phone' => $data['number']]);
    
                    return redirect()->back()->with('success_message', 'User name & number updated');
                }
                else if($image == 0 && $name == 1 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['name' => $data['name'], 'phone' => $data['number'], 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User name, number & notes updated');
                }
                else if($image == 1 && $name == 0 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName]);
    
                    return redirect()->back()->with('success_message', 'User image was updated');
                }
                else if($image == 1 && $name == 0 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User image & notes updated');
                }
                else if($image == 1 && $name == 0 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'phone' => $data['number']]);
    
                    return redirect()->back()->with('success_message', 'User image & number updated');
                }
                else if($image == 1 && $name == 0 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'phone' => $data['number'], 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User image, number & notes updated');
                }
                else if($image == 1 && $name == 1 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name']]);
    
                    return redirect()->back()->with('success_message', 'User image & name updated');
                }
                else if($image == 1 && $name == 1 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name'], 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User image, name & notes updated');
                }
                else if($image == 1 && $name == 1 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name'], 'phone' => $data['number']]);
    
                    return redirect()->back()->with('success_message', 'User name, number & number updated');
                }
                else if($image == 1 && $name == 1 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => $imageName, 'name' => $data['name'], 'phone' => $data['number'], 'notes' => $data['note']]);
    
                    return redirect()->back()->with('success_message', 'User details updated');
                }
                else
                {
                    return redirect()->back()->with('error_message', 'Invalid data, please try again')->withInput($request->input());
                }
            }
        }
        else if (Auth::guard('admin')->user()->type == "vendor")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else
        {
            Auth::guard('admin')->logout();
 
            Session::flush();

            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }

        return view('admin.settings.admin-account')->with(compact('userDetails'));
    }

    /**
     * Update Vendor Details
     *
     * @param Request $request
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View|\Illuminate\Http\RedirectResponse
     * @throws \Illuminate\Validation\ValidationException
     */

    public function requestAccount(Request $request)
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else if (Auth::guard('admin')->user()->type == "vendor")
        {
            Session::put('page', 'accounts');

            // This function will be required if Admin approves the status - to update Vendor (keeping it temporarily here)
            // if(Auth::guard('admin')->user()->vendor_update_status == 0)
            // {
            //     $originalDetails = Admin::where('email', Auth::guard('admin')->user()->email)->first()->toArray();
            //     $userDetails = Admin::where('email', Auth::guard('admin')->user()->email)->first()->toArray();
            //     $decodeMessage = Auth::guard('admin')->user()->notes;
            //     $hasImage = strpos($decodeMessage, "Image:") !== false;
            //     $hasName = strpos($decodeMessage, "Name:") !== false;
            //     $hasNumber = strpos($decodeMessage, "Number:") !== false;
            //     $hasNotes = strpos($decodeMessage, "Notes:") !== false;
            //     if ($hasImage || $hasName || $hasNumber || $hasNotes)
            //     {
            //         $keyValues = explode(", ", $decodeMessage);
            //         $data = [];
            //         foreach ($keyValues as $keyValue) {
            //             list($key, $value) = explode(":", $keyValue);
            //             $data[$key] = $value;
            //         }
            //         if(isset($data['Image']))
            //         {
            //             $userDetails['image'] = str_replace(" ", "", $data['Image']);
            //         }
            //         if(isset($data['Name']))
            //         {
            //             $userDetails['name'] = str_replace(" ", "", $data['Name']);
            //         }
            //         if(isset($data['Number']))
            //         {
            //             $userDetails['phone'] = str_replace(" ", "", $data['Number']);
            //         }
            //         if(isset($data['Notes']))
            //         {
            //             $userDetails['notes'] = str_replace(" ", "", $data['Notes']);
            //         }
            //         if(!isset($data['Notes']))
            //         {
            //             $userDetails['notes'] = '';
            //         }
            //     }
            // }
            if(Auth::guard('admin')->user()->vendor_update_status == 1)
            {
                $originalDetails = Admin::where('email', Auth::guard('admin')->user()->email)->first()->toArray();
                $userDetails = Admin::where('email', Auth::guard('admin')->user()->email)->first()->toArray();
                $decodeMessage = Auth::guard('admin')->user()->notes;
                $hasImage = strpos($decodeMessage, "Image:") !== false;
                $hasName = strpos($decodeMessage, "Name:") !== false;
                $hasNumber = strpos($decodeMessage, "Number:") !== false;
                $hasNotes = strpos($decodeMessage, "Notes:") !== false;
                if ($hasImage || $hasName || $hasNumber || $hasNotes)
                {
                    $keyValues = explode(", ", $decodeMessage);
                    $data = [];
                    foreach ($keyValues as $keyValue) {
                        list($key, $value) = explode(":", $keyValue);
                        $data[$key] = $value;
                    }
                    if(isset($data['Image']))
                    {
                        $userDetails['image'] = str_replace(" ", "", $data['Image']);
                    }
                    if(isset($data['Name']))
                    {
                        $userDetails['name'] = str_replace(" ", "", $data['Name']);
                    }
                    if(isset($data['Number']))
                    {
                        $userDetails['phone'] = str_replace(" ", "", $data['Number']);
                    }
                    if(isset($data['Notes']))
                    {
                        $userDetails['notes'] = str_replace(" ", "", $data['Notes']);
                    }
                    if(!isset($data['Notes']))
                    {
                        $userDetails['notes'] = '';
                    }
                }
            }
    
            if($request->isMethod('POST') && Auth::guard('admin')->user()->vendor_update_status == 0)
            {
                $data = $request->all();
    
                $rules = [
                    'name' => 'nullable|min:3|regex:/^[-_ a-zA-Z0-9]+$/',
                    'number' => 'nullable|min:8|regex:/^([0-9\s\-\+\(\)]*)$/',
                    'adminImage' => 'nullable|mimes:jpeg,jpg,png',
                    'note' => 'nullable|min:3|max:2048|regex:/^[A-Za-z0-9,:\.\s]+$/'
                ];
                $customMessages = [
                    'name.min' => 'The name is too short.',
                    'name.regex' => 'The name has unauthorised characters.',
                    'number.min' => 'The number is too short.',
                    'number.regex' => 'The number is in invalid format.',
                    'adminImage.mimes' => 'Invalid image format. Allowed: jpeg, jpg, png.',
                    'note.min' => 'Note is too short. Please type more.',
                    'note.max' => 'Note is too large. Please reduce size to 2000 characters.',
                    'note.regex' => 'The note is in invalid format.',
                ];
    
                $this->validate($request, $rules, $customMessages);

                $constantString = "Image: , Name: , Number: , Notes: , DeleteImage: , DeleteNotes: ";

                $imageData = null;
                $nameData = null;
                $numberData = null;
                $notesData = null;
    
                $image = 0;
                $name = 0;
                $number = 0;
                $note = 0;
    
                if($request->hasFile('adminImage'))
                {
                    $image_tmp = $request->file('adminImage');
    
                    if ($image_tmp->isValid())
                    {
                        $extension = $image_tmp->getClientOriginalExtension();
                        $imageName = time() . mt_rand() . '.' . $extension;

                        $folderPath = 'admin/images/admin_images/';

                        if (!File::exists($folderPath)) 
                        {
                            File::makeDirectory($folderPath);
                        }
    
                        $imagePath = 'admin/images/admin_images/' . $imageName;
    
                        Image::make($image_tmp)->resize(300, 400)->save($imagePath);
                    }
    
                    $image = 1;
                    $constantString = str_replace("Image: ,", "Image: " . $imageName . ",", $constantString);
                }
                else
                {
                    $constantString = str_replace("Image: ,", "Image: " . $originalDetails['image'] . ",", $constantString);
                }
    
                if($request->has('name') && $data['name'] != '' && $originalDetails['name'] != $data['name'])
                {
                    $name = 1;
                    $constantString = str_replace("Name: ,", "Name: " . $data['name'] . ",", $constantString);
                }
    
                if($request->has('number') && $data['number'] != '' && $originalDetails['phone'] != $data['number'])
                {
                    $number = 1;
                    $constantString = str_replace("Number: ,", "Number: " . $data['number'] . ",", $constantString);
                }
    
                if($request->has('note') && $data['note'] != '' && $originalDetails['notes'] != $data['note'])
                {
                    $note = 1;
                    $constantString = str_replace("Notes: ,", "Notes: " . $data['note'] . ",", $constantString);
                }
    
                if($image == 0 && $name == 0 && $number == 0 && $note == 0)
                {
                    return redirect()->back()->with('neutral_message', 'No updates were Requested.');
                }
                else if($image == 0 && $name == 0 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User notes updated Requested');
                }
                else if($image == 0 && $name == 0 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User number updated Requested');
                }
                else if($image == 0 && $name == 0 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User number & notes updated Requested');
                }
                else if($image == 0 && $name == 1 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User name updated Requested');
                }
                else if($image == 0 && $name == 1 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User name & notes updated Requested');
                }
                else if($image == 0 && $name == 1 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User name & number updated Requested');
                }
                else if($image == 0 && $name == 1 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User name, number & notes updated Requested');
                }
                else if($image == 1 && $name == 0 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User image was updated Requested');
                }
                else if($image == 1 && $name == 0 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User image & notes updated Requested');
                }
                else if($image == 1 && $name == 0 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User image & number updated Requested');
                }
                else if($image == 1 && $name == 0 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User image, number & notes updated Requested');
                }
                else if($image == 1 && $name == 1 && $number == 0 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User image & name updated Requested');
                }
                else if($image == 1 && $name == 1 && $number == 0 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User image, name & notes updated Requested');
                }
                else if($image == 1 && $name == 1 && $number == 1 && $note == 0)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User name, number & number updated Requested');
                }
                else if($image == 1 && $name == 1 && $number == 1 && $note == 1)
                {
                    Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => $constantString, 'vendor_update_status' => '1']);
    
                    return redirect()->back()->with('success_message', 'User details updated Requested');
                }
                else
                {
                    return redirect()->back()->with('error_message', 'Invalid data, please try again')->withInput($request->input());
                }
            }
            elseif($request->isMethod('POST') && Auth::guard('admin')->user()->vendor_update_status == 1)
            {
                return redirect('/admin/error/501')->with('error_message', 'Invalid Request. You can not make this request.');
            }
        }
        else
        {
            Auth::guard('admin')->logout();  
            Session::flush(); 
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }

        return view('admin.settings.request-account')->with(compact('userDetails'));
    }

    /**
     * Approve Vendor Details
     *
     * @param Request $request
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View|\Illuminate\Http\RedirectResponse
     * @throws \Illuminate\Validation\ValidationException
     */

    public function approve(Request $request)
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            Session::put('page', 'accounts');
 
            $userDetails = Admin::where('type', 'vendor')->get();
        }

        return view('admin.settings.admin-vendor')->with(compact('userDetails'));
    }

    /**
     * Check User Password
     *
     * @param Request $request
     * @return void
     */

    public function checkCurrentPassword(Request $request)
    {
        $data = $request->all();

        if (Hash::check($data['current_password'], Auth::guard('admin')->user()->password))
        {
            echo 'True';
        }
        else
        {
            echo 'False';
        }
    }

    /**
     * Delete Vendor Notes
     *
     * @return \Illuminate\Http\RedirectResponse
     */

    public function deleteVendorNotes()
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else if (Auth::guard('admin')->user()->type == "vendor" && Auth::guard('admin')->user()->vendor_update_status == 1)
        {
            // Update Vendor Notes Delete Post Approval
        }
        else
        {
            Auth::guard('admin')->logout();
 
            Session::flush();

            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }
    }

    /**
     * Delete Vendor Images
     *
     * @return \Illuminate\Http\RedirectResponse
     */

    public function deleteVendorImage()
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else if (Auth::guard('admin')->user()->type == "vendor"  && Auth::guard('admin')->user()->vendor_update_status == 1)
        {
            // Update Vendor Image Delete Post Approval
        }
        else
        {
            Auth::guard('admin')->logout();
 
            Session::flush();

            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }
    }

    /**
     * Delete Admin Notes
     *
     * @return \Illuminate\Http\RedirectResponse
     */

    public function deleteAdminNotes()
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            $request = app()->make(Request::class);

            if ($request->method() === 'GET')
            {
                Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => null]);
    
                return redirect()->back()->with('success_message', 'Notes removed successfully');
            }
            else
            {
                return redirect()->back()->with('error_message', 'Invalid Request, Please try again');
            }
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            $request = app()->make(Request::class);

            if ($request->method() === 'GET')
            {
                Admin::where('id', Auth::guard('admin')->user()->id)->update(['notes' => null]);
    
                return redirect()->back()->with('success_message', 'Notes removed successfully');
            }
            else
            {
                return redirect()->back()->with('error_message', 'Invalid Request, Please try again');
            }
        }
        else if (Auth::guard('admin')->user()->type == "vendor")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else
        {
            Auth::guard('admin')->logout();
 
            Session::flush();

            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }
    }
 
     /**
      * Delete Admin Images
      *
      * @return \Illuminate\Http\RedirectResponse
      */
 
    public function deleteAdminImage()
    {
        if (Auth::guard('admin')->user()->type == "admin")
        {
            $request = app()->make(Request::class);
 
            if ($request->method() === 'GET')
            {
                $imageName = Admin::select('image')->where('id', Auth::guard('admin')->user()->id)->first();
     
                $image_path = 'admin/images/admin_images/' . $imageName->image;
         
                // File::delete($large_image_path, $medium_image_path, $small_image_path);
                if (file_exists($image_path) && !empty($imageName->image))
                {
                    unlink($image_path);
                }
         
                Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => '']);
         
                return redirect()->back()->with('success_message', 'Image removed successfully');
            }
            else
            {
                return redirect()->back()->with('error_message', 'Invalid Request, Please try again');
            }
        }
        else if (Auth::guard('admin')->user()->type == "sub-admin")
        {
            $request = app()->make(Request::class);
 
            if ($request->method() === 'GET')
            {
                $imageName = Admin::select('image')->where('id', Auth::guard('admin')->user()->id)->first();
     
                $image_path = 'admin/images/admin_images/' . $imageName->image;
         
                // File::delete($large_image_path, $medium_image_path, $small_image_path);
                if (file_exists($image_path) && !empty($imageName->image))
                {
                    unlink($image_path);
                }
         
                Admin::where('id', Auth::guard('admin')->user()->id)->update(['image' => '']);
         
                return redirect()->back()->with('success_message', 'Image removed successfully');
            }
            else
            {
                return redirect()->back()->with('error_message', 'Invalid Request, Please try again');
            }
        }
        else if (Auth::guard('admin')->user()->type == "vendor")
        {
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. You do not have access to this page.');
        }
        else
        {
            Auth::guard('admin')->logout();
  
            Session::flush();
 
            return redirect('/admin/error/404')->with('error_message', 'Invalid Request. Logging you Out.');
        }
    }

    /**
     * Error Pages
     *
     * @param $slug
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View|void1
     */

    public function error($slug = null)
    {
        if($slug != null)
        {
            return view('admin.error.custom-error')->with(compact('slug'));
        }
    }

    /**
     * Logout Functionality
     *
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\View\Factory|\Illuminate\Contracts\View\View
     */

    public function logout()
    {
        Auth::guard('admin')->logout();
 
        Session::flush();
 
        return redirect('/admin/login')->with('success_message', 'Logout Successful');
    }

}
