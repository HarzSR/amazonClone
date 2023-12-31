<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Admin\Vendor;
use DB;

class VendorSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        //

        DB::table('vendors')->truncate();

        $vendorRecords = [
            ['name' => 'Vendor 1', 'address' => 'Address 1', 'city' => 'City 1', 'state' => 'State 1', 'country' => 'Country 1', 'code' => '000001', 'phone' => '1234567890', 'email' => 'vendor1@vendor.com'],
            ['name' => 'Vendor 2', 'address' => 'Address 2', 'city' => 'City 2', 'state' => 'State 2', 'country' => 'Country 2', 'code' => '000002', 'phone' => '1234567890', 'email' => 'vendor2@vendor.com'],
        ];

        // DB::table('vendors')->insert($vendorRecords);

        foreach ($vendorRecords as $key => $record)
        {
            Vendor::create($record);
        }
    }
}
